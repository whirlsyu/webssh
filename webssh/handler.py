import io
import json
import logging
import socket
import struct
import traceback
import weakref
import paramiko
import tornado.web
import docker
import uuid
import time

from concurrent.futures import ThreadPoolExecutor
from tornado.ioloop import IOLoop
from tornado.options import options
from tornado.process import cpu_count
from webssh.utils import (
    is_valid_ip_address, is_valid_port, is_valid_hostname, to_bytes, to_str,
    to_int, to_ip_address, UnicodeType, is_ip_hostname, is_same_primary_domain,
    is_valid_encoding
)
from webssh.worker import Worker, recycle_worker, clients

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


from urllib.parse import urlparse



DEFAULT_PORT = 22

swallow_http_errors = True
redirecting = None

def check_ssh_keys(container, timeout=30):
    """检查容器SSH密钥是否生成"""
    start = time.time()
    required_keys = [
        '/etc/ssh/ssh_host_rsa_key',
        '/etc/ssh/ssh_host_ecdsa_key', 
        '/etc/ssh/ssh_host_ed25519_key'
    ]
    
    while time.time() - start < timeout:
        try:
            # 执行检查命令
            exit_code, output = container.exec_run(f"ls {' '.join(required_keys)}")
            
            if exit_code == 0:
                logging.debug("所有SSH密钥文件已存在")
                return True
                
            # 记录详细错误信息
            missing = []
            for key in required_keys:
                ec, _ = container.exec_run(f"ls {key}")
                if ec != 0:
                    missing.append(key)
                    
            logging.warning(f"缺失的密钥文件：{missing}")
            
        except docker.errors.APIError as e:
            logging.error(f"Docker API错误：{str(e)}")
            if "is not running" in str(e):
                logging.error("容器已停止，无法检查密钥")
                return False
                
        time.sleep(1)
        
    logging.error(f"SSH密钥检查超时（{timeout}秒）")
    return False

class InvalidValueError(Exception):
    pass


class SSHClient(paramiko.SSHClient):

    def handler(self, title, instructions, prompt_list):
        answers = []
        for prompt_, _ in prompt_list:
            prompt = prompt_.strip().lower()
            if prompt.startswith('password'):
                answers.append(self.password)
            elif prompt.startswith('verification'):
                answers.append(self.totp)
            else:
                raise ValueError('Unknown prompt: {}'.format(prompt_))
        return answers

    def auth_interactive(self, username, handler):
        if not self.totp:
            raise ValueError('Need a verification code for 2fa.')
        self._transport.auth_interactive(username, handler)

    def _auth(self, username, password, pkey, *args):
        self.password = password
        saved_exception = None
        two_factor = False
        allowed_types = set()
        two_factor_types = {'keyboard-interactive', 'password'}

        if pkey is not None:
            logging.info('Trying publickey authentication')
            try:
                allowed_types = set(
                    self._transport.auth_publickey(username, pkey)
                )
                two_factor = allowed_types & two_factor_types
                if not two_factor:
                    return
            except paramiko.SSHException as e:
                saved_exception = e

        if two_factor:
            logging.info('Trying publickey 2fa')
            return self.auth_interactive(username, self.handler)

        if password is not None:
            logging.info('Trying password authentication')
            try:
                self._transport.auth_password(username, password)
                return
            except paramiko.SSHException as e:
                saved_exception = e
                allowed_types = set(getattr(e, 'allowed_types', []))
                two_factor = allowed_types & two_factor_types

        if two_factor:
            logging.info('Trying password 2fa')
            return self.auth_interactive(username, self.handler)

        assert saved_exception is not None
        raise saved_exception


class PrivateKey(object):

    max_length = 16384  # rough number

    tag_to_name = {
        'RSA': 'RSA',
        'DSA': 'DSS',
        'EC': 'ECDSA',
        'OPENSSH': 'Ed25519'
    }

    def __init__(self, privatekey, password=None, filename=''):
        self.privatekey = privatekey
        self.filename = filename
        self.password = password
        self.check_length()
        self.iostr = io.StringIO(privatekey)
        self.last_exception = None

    def check_length(self):
        if len(self.privatekey) > self.max_length:
            raise InvalidValueError('Invalid key length.')

    def parse_name(self, iostr, tag_to_name):
        name = None
        for line_ in iostr:
            line = line_.strip()
            if line and line.startswith('-----BEGIN ') and \
                    line.endswith(' PRIVATE KEY-----'):
                lst = line.split(' ')
                if len(lst) == 4:
                    tag = lst[1]
                    if tag:
                        name = tag_to_name.get(tag)
                        if name:
                            break
        return name, len(line_)

    def get_specific_pkey(self, name, offset, password):
        self.iostr.seek(offset)
        logging.debug('Reset offset to {}.'.format(offset))

        logging.debug('Try parsing it as {} type key'.format(name))
        pkeycls = getattr(paramiko, name+'Key')
        pkey = None

        try:
            pkey = pkeycls.from_private_key(self.iostr, password=password)
        except paramiko.PasswordRequiredException:
            raise InvalidValueError('Need a passphrase to decrypt the key.')
        except (paramiko.SSHException, ValueError) as exc:
            self.last_exception = exc
            logging.debug(str(exc))

        return pkey

    def get_pkey_obj(self):
        logging.info('Parsing private key {!r}'.format(self.filename))
        name, length = self.parse_name(self.iostr, self.tag_to_name)
        if not name:
            raise InvalidValueError('Invalid key {}.'.format(self.filename))

        offset = self.iostr.tell() - length
        password = to_bytes(self.password) if self.password else None
        pkey = self.get_specific_pkey(name, offset, password)

        if pkey is None and name == 'Ed25519':
            for name in ['RSA', 'ECDSA', 'DSS']:
                pkey = self.get_specific_pkey(name, offset, password)
                if pkey:
                    break

        if pkey:
            return pkey

        logging.error(str(self.last_exception))
        msg = 'Invalid key'
        if self.password:
            msg += ' or wrong passphrase "{}" for decrypting it.'.format(
                    self.password)
        raise InvalidValueError(msg)


class MixinHandler(object):

    custom_headers = {
        'Server': 'TornadoServer'
    }

    html = ('<html><head><title>{code} {reason}</title></head><body>{code} '
            '{reason}</body></html>')

    def initialize(self, loop=None):
        self.check_request()
        self.loop = loop
        self.origin_policy = self.settings.get('origin_policy')

    def check_request(self):
        context = self.request.connection.context
        result = self.is_forbidden(context, self.request.host_name)
        self._transforms = []
        if result:
            self.set_status(403)
            self.finish(
                self.html.format(code=self._status_code, reason=self._reason)
            )
        elif result is False:
            to_url = self.get_redirect_url(
                self.request.host_name, options.sslport, self.request.uri
            )
            self.redirect(to_url, permanent=True)
        else:
            self.context = context

    def check_origin(self, origin):
        if self.origin_policy == '*':
            return True

        parsed_origin = urlparse(origin)
        netloc = parsed_origin.netloc.lower()
        logging.debug('netloc: {}'.format(netloc))

        host = self.request.headers.get('Host')
        logging.debug('host: {}'.format(host))

        if netloc == host:
            return True

        if self.origin_policy == 'same':
            return False
        elif self.origin_policy == 'primary':
            return is_same_primary_domain(netloc.rsplit(':', 1)[0],
                                          host.rsplit(':', 1)[0])
        else:
            return origin in self.origin_policy

    def is_forbidden(self, context, hostname):
        ip = context.address[0]
        lst = context.trusted_downstream
        ip_address = None

        if lst and ip not in lst:
            logging.warning(
                'IP {!r} not found in trusted downstream {!r}'.format(ip, lst)
            )
            return True

        if context._orig_protocol == 'http':
            if redirecting and not is_ip_hostname(hostname):
                ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    # redirecting
                    return False

            if options.fbidhttp:
                if ip_address is None:
                    ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    logging.warning('Public plain http request is forbidden.')
                    return True

    def get_redirect_url(self, hostname, port, uri):
        port = '' if port == 443 else ':%s' % port
        return 'https://{}{}{}'.format(hostname, port, uri)

    def set_default_headers(self):
        for header in self.custom_headers.items():
            self.set_header(*header)

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise InvalidValueError('Missing value {}'.format(name))
        return value

    def get_context_addr(self):
        return self.context.address[:2]

    def get_client_addr(self):
        if options.xheaders:
            return self.get_real_client_addr() or self.get_context_addr()
        else:
            return self.get_context_addr()

    def get_real_client_addr(self):
        ip = self.request.remote_ip

        if ip == self.request.headers.get('X-Real-Ip'):
            port = self.request.headers.get('X-Real-Port')
        elif ip in self.request.headers.get('X-Forwarded-For', ''):
            port = self.request.headers.get('X-Forwarded-Port')
        else:
            # not running behind an nginx server
            return

        port = to_int(port)
        if port is None or not is_valid_port(port):
            # fake port
            port = 65535

        return (ip, port)


class NotFoundHandler(MixinHandler, tornado.web.ErrorHandler):

    def initialize(self):
        super(NotFoundHandler, self).initialize()

    def prepare(self):
        raise tornado.web.HTTPError(404)


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    executor = ThreadPoolExecutor(max_workers=cpu_count()*5)

    def initialize(self, loop, policy, host_keys_settings):
        super(IndexHandler, self).initialize(loop)
        self.policy = policy
        self.host_keys_settings = host_keys_settings
        self.ssh_client = self.get_ssh_client()
        self.debug = self.settings.get('debug', False)
        self.font = self.settings.get('font', '')
        self.result = dict(id=None, status=None, encoding=None)
        self.conteiner = None
        self.dockerargs = docker_args = {
                                            "image": "ssh-enabled:latest",
                                            #"command": "/bin/bash",
                                            "auto_remove": True,
                                            #"volumes": {"/host/path": {"bind": "/container/path", "mode": "rw"}},
                                            "ports":{'22/tcp': 2222},     # 映射宿主机2222端口到容器22端口[1](@ref)
                                            #"environment": {"ENV_VAR": "value"}
                                        }

    def write_error(self, status_code, **kwargs):
        if swallow_http_errors and self.request.method == 'POST':
            exc_info = kwargs.get('exc_info')
            if exc_info:
                reason = getattr(exc_info[1], 'log_message', None)
                if reason:
                    self._reason = reason
            self.result.update(status=self._reason)
            self.set_status(200)
            self.finish(self.result)
        else:
            super(IndexHandler, self).write_error(status_code, **kwargs)

    def get_ssh_client(self):
        ssh = SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        ssh._host_keys = self.host_keys_settings['host_keys']
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)
        return ssh

    def get_privatekey(self):
        name = 'privatekey'
        lst = self.request.files.get(name)
        if lst:
            # multipart form
            filename = lst[0]['filename']
            data = lst[0]['body']
            value = self.decode_argument(data, name=name).strip()
        else:
            # urlencoded form
            value = self.get_argument(name, u'')
            filename = ''

        return value, filename

    def get_hostname(self):
        value = self.get_value('hostname')
        if not (is_valid_hostname(value) or is_valid_ip_address(value)):
            raise InvalidValueError('Invalid hostname: {}'.format(value))
        return value

    def get_port(self):
        value = self.get_argument('port', u'')
        if not value:
            return DEFAULT_PORT

        port = to_int(value)
        if port is None or not is_valid_port(port):
            raise InvalidValueError('Invalid port: {}'.format(value))
        return port

    def lookup_hostname(self, hostname, port):
        key = hostname if port == 22 else '[{}]:{}'.format(hostname, port)

        if self.ssh_client._system_host_keys.lookup(key) is None:
            if self.ssh_client._host_keys.lookup(key) is None:
                raise tornado.web.HTTPError(
                        403, 'Connection to {}:{} is not allowed.'.format(
                            hostname, port)
                    )

    def get_args(self):
        hostname = self.get_hostname()
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password', u'')
        privatekey, filename = self.get_privatekey()
        passphrase = self.get_argument('passphrase', u'')
        totp = self.get_argument('totp', u'')

        if isinstance(self.policy, paramiko.RejectPolicy):
            self.lookup_hostname(hostname, port)

        if privatekey:
            pkey = PrivateKey(privatekey, passphrase, filename).get_pkey_obj()
        else:
            pkey = None

        self.ssh_client.totp = totp
        args = (hostname, port, username, password, pkey)
        logging.debug(args)

        return args

    def parse_encoding(self, data):
        try:
            encoding = to_str(data.strip(), 'ascii')
        except UnicodeDecodeError:
            return

        if is_valid_encoding(encoding):
            return encoding

    def get_default_encoding(self, ssh):
        commands = [
            '$SHELL -ilc "locale charmap"',
            '$SHELL -ic "locale charmap"'
        ]

        for command in commands:
            try:
                _, stdout, _ = ssh.exec_command(command,
                                                get_pty=True,
                                                timeout=1)
            except paramiko.SSHException as exc:
                logging.info(str(exc))
            else:
                try:
                    data = stdout.read()
                except socket.timeout:
                    pass
                else:
                    logging.debug('{!r} => {!r}'.format(command, data))
                    result = self.parse_encoding(data)
                    if result:
                        return result

        logging.warning('Could not detect the default encoding.')
        return 'utf-8'

    def docker(self, docker_args):
        """创建一个Docker容器并返回DockerWorker对象"""
        try:
            client = docker.from_env()
        except Exception as e:
            logging.error(f'连接Docker失败: {str(e)}')
            raise ValueError(f'连接Docker失败: {str(e)}')
        
        # 获取Docker参数
        image = docker_args.get('image')
        container_name = docker_args.get('name')
        
        # 为容器生成唯一名称，避免冲突
        if not container_name:
            container_name = f'webssh_{uuid.uuid4().hex[:8]}'
        else:
            # 如果指定了名称，则添加随机后缀以避免冲突
            container_name = f'{container_name}_{uuid.uuid4().hex[:6]}'
        
        docker_args["ports"]["22/tcp"] = int(self.get_value('port')) # 将宿主机端口映射到容器端口   
        #cmd = docker_args.get('cmd') or '/bin/bash'
        cmd = docker_args.get('cmd') or None
        working_dir = docker_args.get('working_dir')
        volumes = docker_args.get('volumes') or []
        #ports = docker_args.get('ports') or {}
        #ports = self.get_value('port') or {}
        environment = docker_args.get('environment') or {}
        
        # 检查容器名称是否存在，如果存在则移除
        try:
            existing_container = client.containers.get(container_name)
            logging.info(f'找到同名容器，正在移除: {container_name}')
            existing_container.remove(force=True)
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logging.error(f'移除已存在容器时出错: {str(e)}')
            # 如果无法移除已存在容器，生成一个新的随机名称
            container_name = f'webssh_{uuid.uuid4().hex}'
            logging.info(f'生成新的容器名称: {container_name}')
        
        max_retries = 20
        base_port = docker_args["ports"]["22/tcp"]
        current_port = base_port
        
        for attempt in range(max_retries):
            try:
                docker_args["ports"]["22/tcp"] = current_port
                logging.info(f'创建Docker容器: 镜像={image}, 命令={cmd}, 名称={container_name}')
                
                self.container = client.containers.run(
                    image=image,
                    command=cmd,
                    name=container_name,
                    working_dir=working_dir,
                    volumes=volumes,
                    ports=docker_args["ports"],  # 使用动态端口
                    environment=environment,
                    detach=True,
                    tty=True,
                    stdin_open=True,
                    remove=False,
                    privileged=True  # 可选：启用特权模式
                )
                if not check_ssh_keys(self.container):
                    self.container.remove(force=True)
                    raise RuntimeError("SSH密钥生成失败，已清理容器")

                # 同时添加容器日志检查
                logs = self.container.logs().decode()
                if "Server listening on" not in logs:
                    logging.error("SSHD未正确启动，容器日志：%s", logs)
                                
                times = 0
                while not self.is_port_open('localhost', docker_args["ports"]["22/tcp"]) and times < 10:
                    logging.info(f'等待容器启动: {container_name}:{docker_args["ports"]["22/tcp"]}')
                    times += 1
                    time.sleep(1)
                
                # 检查容器是否正在运行
                #self.container.reload()
                if self.container.status != 'running' and self.container.status != 'created':
                    logging.error(f'容器未能正常启动，状态为: {self.container.status}')
                    raise ValueError(f'容器未能正常启动，状态为: {self.container.status}')
                else:
                    break
                
            except Exception as e:
                logging.error(f'创建Docker容器失败: {str(e)}')
                if 'port is already allocated' in str(e).lower():
                    logging.warning(f'端口 {current_port} 被占用，尝试端口 {current_port + 1}')
                    existing_container = client.containers.get(container_name)
                    logging.info(f'找到失败容器，正在移除: {container_name}')
                    existing_container.remove(force=True)
                    current_port += 1
                    continue
                else:                
                    try:
                        if 'container' in locals():
                            self.container.remove(force=True)
                    except:
                        pass
                    raise ValueError(f'创建Docker容器失败: {str(e)}')
        else:
            raise ValueError(f"连续 {max_retries} 次端口尝试失败")
        
        return (container_name, current_port)
            

    def is_port_open(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 设置1秒超时
            return s.connect_ex((host, port)) == 0
    def ssh_connect(self, args):
        ssh = self.ssh_client
        dst_addr = args[:2]
        if args[0] == 'localhost':
            try:
                container_name, current_port =  self.docker(self.dockerargs)
                temp_list = list(args)
                temp_list[1] = current_port
                argsn = tuple(temp_list)
            except Exception as e:
                raise ValueError(f'创建Docker容器失败: {str(e)}')
            logging.info('Connecting to {}:{}'.format(*dst_addr))

        try:            
            ssh.connect(*argsn, timeout=options.timeout)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Bad authentication type.')
        except paramiko.AuthenticationException:
            raise ValueError('Authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')

        term = self.get_argument('term', u'') or u'xterm'
        chan = ssh.invoke_shell(term=term)
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr,self.container)
        worker.encoding = options.encoding if options.encoding else \
            self.get_default_encoding(ssh)
        return worker

    def check_origin(self):
        event_origin = self.get_argument('_origin', u'')
        header_origin = self.request.headers.get('Origin')
        origin = event_origin or header_origin

        if origin:
            if not super(IndexHandler, self).check_origin(origin):
                raise tornado.web.HTTPError(
                    403, 'Cross origin operation is not allowed.'
                )

            if not event_origin and self.origin_policy != 'same':
                self.set_header('Access-Control-Allow-Origin', origin)

    def head(self):
        pass

    def get(self):
        self.render('index.html', debug=self.debug, font=self.font)

    @tornado.gen.coroutine
    def post(self):
        if self.debug and self.get_argument('error', u''):
            # for testing purpose only
            raise ValueError('Uncaught exception')

        ip, port = self.get_client_addr()
        workers = clients.get(ip, {})
        if workers and len(workers) >= options.maxconn:
            raise tornado.web.HTTPError(403, 'Too many live connections.')

        self.check_origin()

        try:
            args = self.get_args()
        except InvalidValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))

        future = self.executor.submit(self.ssh_connect, args)

        try:
            worker = yield future
        except (ValueError, paramiko.SSHException) as exc:
            logging.error(traceback.format_exc())
            self.result.update(status=str(exc))
        else:
            if not workers:
                clients[ip] = workers
            worker.src_addr = (ip, port)
            workers[worker.id] = worker
            self.loop.call_later(options.delay, recycle_worker, worker)
            self.result.update(id=worker.id, encoding=worker.encoding)

        self.write(self.result)


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        super(WsockHandler, self).initialize(loop)
        self.worker_ref = None

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))

        workers = clients.get(self.src_addr[0])
        if not workers:
            self.close(reason='Websocket authentication failed.')
            return

        try:
            worker_id = self.get_value('id')
        except (tornado.web.MissingArgumentError, InvalidValueError) as exc:
            self.close(reason=str(exc))
        else:
            worker = workers.get(worker_id)
            if worker:
                workers[worker_id] = None
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
            else:
                self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        if not worker:
            # The worker has likely been closed. Do not process.
            logging.debug(
                "received message to closed worker from {}:{}".format(
                    *self.src_addr
                )
            )
            self.close(reason='No worker found')
            return

        if worker.closed:
            self.close(reason='Worker closed')
            return

        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        if not self.close_reason:
            self.close_reason = 'client disconnected'

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
