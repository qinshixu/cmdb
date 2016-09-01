#!/usr/bin/env python
#coding:utf8

import sys

reload(sys)
sys.setdefaultencoding('utf8')

import os
import re
import time
import datetime
import textwrap
import getpass
import readline
import django
import paramiko
import errno
import pyte
import operator
import struct, fcntl, signal, socket, select
from io import open as copen
import uuid
import termios
import tty

def color_print(msg, color='red', exits=False):
    """
    Print colorful string.

    """
    color_msg = {'blue': '\033[1;36m%s\033[0m',
                 'green': '\033[1;32m%s\033[0m',
                 'yellow': '\033[1;33m%s\033[0m',
                 'red': '\033[1;31m%s\033[0m',
                 'title': '\033[30;42m%s\033[0m',
                 'info': '\033[32m%s\033[0m'}
    msg = color_msg.get(color, 'red') % msg
    print msg
    if exits:
        time.sleep(2)
        sys.exit()
    return msg


def write_log(f, msg):
    msg = re.sub(r'[\r\n]', '\r\n', msg)
    f.write(msg)
    f.flush()


class Tty(object):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志，基类
    """
    def __init__(self,login_type='ssh'):
        self.username = 'root'
        self.asset='admin'
        self.ip = None
        self.port = 22
        self.ssh = None
        self.channel = None
        self.user = 'root'
        self.remote_ip = ''
        self.login_type = login_type
        self.vim_flag = False
        self.vim_end_pattern = re.compile(r'\x1b\[\?1049', re.X)
        self.vim_data = ''
        self.stream = None
        self.screen = None
        self.__init_screen_stream()

    def __init_screen_stream(self):
        """
        初始化虚拟屏幕和字符流
        """
        self.stream = pyte.ByteStream()
        self.screen = pyte.Screen(80, 24)
        self.stream.attach(self.screen)

    @staticmethod
    def is_output(strings):
        newline_char = ['\n', '\r', '\r\n']
        for char in newline_char:
            if char in strings:
                return True
        return False

    @staticmethod
    def command_parser(command):
        """
        处理命令中如果有ps1或者mysql的特殊情况,极端情况下会有ps1和mysql
        :param command:要处理的字符传
        :return:返回去除PS1或者mysql字符串的结果
        """
        result = None
        match = re.compile('\[?.*@.*\]?[\$#]\s').split(command)
        if match:
            # 只需要最后的一个PS1后面的字符串
            result = match[-1].strip()
        else:
            # PS1没找到,查找mysql
            match = re.split('mysql>\s', command)
            if match:
                # 只需要最后一个mysql后面的字符串
                result = match[-1].strip()
        return result

    def deal_command(self, data):
        """
        处理截获的命令
        :param data: 要处理的命令
        :return:返回最后的处理结果
        """
        command = ''
        try:
            self.stream.feed(data)
            # 从虚拟屏幕中获取处理后的数据
            for line in reversed(self.screen.buffer):
                line_data = "".join(map(operator.attrgetter("data"), line)).strip()
                if len(line_data) > 0:
                    parser_result = self.command_parser(line_data)
                    if parser_result is not None:
                        # 2个条件写一起会有错误的数据
                        if len(parser_result) > 0:
                            command = parser_result
                    else:
                        command = line_data
                    break
        except Exception:
            pass
        # 虚拟屏幕清空
        self.screen.reset()
        return command

    def get_log(self):
        """
        Logging user command and output.
        记录用户的日志
        """
        tty_log_dir = os.path.join(LOG_DIR, 'tty')
        date_today = datetime.datetime.now()
        date_start = date_today.strftime('%Y%m%d')
        time_start = date_today.strftime('%H%M%S')
        today_connect_log_dir = os.path.join(tty_log_dir, date_start)
        log_file_path = os.path.join(today_connect_log_dir, '%s_%s_%s' % (self.username, self.asset_name, time_start))

        try:
            mkdir(os.path.dirname(today_connect_log_dir), mode=777)
            mkdir(today_connect_log_dir, mode=777)
        except OSError:
            logger.debug('创建目录 %s 失败，请修改%s目录权限' % (today_connect_log_dir, tty_log_dir))
            raise ServerError('创建目录 %s 失败，请修改%s目录权限' % (today_connect_log_dir, tty_log_dir))

        try:
            log_file_f = open(log_file_path + '.log', 'a')
            log_time_f = open(log_file_path + '.time', 'a')
        except IOError:
            logger.debug('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)
            raise ServerError('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)

        if self.login_type == 'ssh':  # 如果是ssh连接过来，记录connect.py的pid，web terminal记录为日志的id
            pid = os.getpid()
            self.remote_ip = remote_ip  # 获取远端IP
        else:
            pid = 0

        log = Log(user=self.username, host=self.asset_name, remote_ip=self.remote_ip, login_type=self.login_type,
                  log_path=log_file_path, start_time=date_today, pid=pid)
        log.save()
        if self.login_type == 'web':
            log.pid = log.id  # 设置log id为websocket的id, 然后kill时干掉websocket
            log.save()

        log_file_f.write('Start at %s\r\n' % datetime.datetime.now())
        return log_file_f, log_time_f, log

    def get_connect_info(self):
        """
        获取需要登陆的主机的信息和映射用户的账号密码
        """
#        asset_info = get_asset_info(self.asset)
#        role_key = get_role_key(self.user, self.role)  # 获取角色的key，因为ansible需要权限是600，所以统一生成用户_角色key
#        role_pass = CRYPTOR.decrypt(self.role.password)
        connect_info = {'user': 'root', 'asset': 'admin', 'ip':'10.0.1.149',
                        'port': 22, 'role_name': 'root',
                        'role_pass':'123456', 'role_key':'/root/.ssh/id_rsa'}
        return connect_info

    def get_connection(self):
        """
        获取连接成功后的ssh
        """
        connect_info = self.get_connect_info()

        # 发起ssh连接请求 Make a ssh connection
        ssh = paramiko.SSHClient()
        # ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            role_key = connect_info.get('role_key')
            print role_key
            if role_key and os.path.isfile(role_key):
                try:
                    ssh.connect(connect_info.get('ip'),
                                port=connect_info.get('port'),
                                username=connect_info.get('role_name'),
                                password=connect_info.get('role_pass'),
                                key_filename=role_key,
                                look_for_keys=False)
                    return ssh
                except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
                    logger.warning(u'使用ssh key %s 失败, 尝试只使用密码' % role_key)
                    pass

            ssh.connect(connect_info.get('ip'),
                        port=connect_info.get('port'),
                        username=connect_info.get('role_name'),
                        password=connect_info.get('role_pass'),
                        allow_agent=False,
                        look_for_keys=False)

        except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
            raise ServerError('认证失败 Authentication Error.')
        except socket.error:
            raise ServerError('端口可能不对 Connect SSH Socket Port Error, Please Correct it.')
        else:
            self.ssh = ssh
            return ssh


class SshTty(Tty):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志
    """

    @staticmethod
    def get_win_size():
        """
        This function use to get the size of the windows!
        获得terminal窗口大小
        """
        if 'TIOCGWINSZ' in dir(termios):
            TIOCGWINSZ = termios.TIOCGWINSZ
        else:
            TIOCGWINSZ = 1074295912L
        s = struct.pack('HHHH', 0, 0, 0, 0)
        x = fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ, s)
        return struct.unpack('HHHH', x)[0:2]

    def set_win_size(self, sig, data):
        """
        This function use to set the window size of the terminal!
        设置terminal窗口大小
        """
        try:
            win_size = self.get_win_size()
            self.channel.resize_pty(height=win_size[0], width=win_size[1])
        except Exception:
            pass

    def posix_shell(self):
        """
        Use paramiko channel connect server interactive.
        使用paramiko模块的channel，连接后端，进入交互式
        """
#        log_file_f, log_time_f, log = self.get_log()
#        termlog = TermLogRecorder(User.objects.get(id=self.user.id))
#        termlog.setid(log.id)
        old_tty = termios.tcgetattr(sys.stdin)
        pre_timestamp = time.time()
        data = ''
        input_mode = False
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self.channel.settimeout(0.0)

            while True:
                try:
                    r, w, e = select.select([self.channel, sys.stdin], [], [])
                    flag = fcntl.fcntl(sys.stdin, fcntl.F_GETFL, 0)
                    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, flag|os.O_NONBLOCK)
                except Exception:
                    pass

                if self.channel in r:
                    try:
                        x = self.channel.recv(10240)
                        if len(x) == 0:
                            break

                        index = 0
                        len_x = len(x)
                        while index < len_x:
                            try:
                                n = os.write(sys.stdout.fileno(), x[index:])
                                sys.stdout.flush()
                                index += n
                            except OSError as msg:
                                if msg.errno == errno.EAGAIN:
                                    continue
                        now_timestamp = time.time()
#                        termlog.write(x)
#                        termlog.recoder = False
#                        log_time_f.write('%s %s\n' % (round(now_timestamp-pre_timestamp, 4), len(x)))
#                        log_time_f.flush()
#                        log_file_f.write(x)
#                        log_file_f.flush()
#                        pre_timestamp = now_timestamp
#                        log_file_f.flush()

                        self.vim_data += x
                        if input_mode:
                            data += x

                    except socket.timeout:
                        pass

                if sys.stdin in r:
                    try:
                        x = os.read(sys.stdin.fileno(), 4096)
                    except OSError:
                        pass
#                    termlog.recoder = True
                    input_mode = True
                    if self.is_output(str(x)):
                        # 如果len(str(x)) > 1 说明是复制输入的
                        if len(str(x)) > 1:
                            data = x
                        match = self.vim_end_pattern.findall(self.vim_data)
                        if match:
                            if self.vim_flag or len(match) == 2:
                                self.vim_flag = False
                            else:
                                self.vim_flag = True
                        elif not self.vim_flag:
                            self.vim_flag = False
                            data = self.deal_command(data)[0:200]
                            if data is not None:
                                pass
#                                TtyLog(log=log, datetime=datetime.datetime.now(), cmd=data).save()
                        data = ''
                        self.vim_data = ''
                        input_mode = False

                    if len(x) == 0:
                        break
                    self.channel.send(x)

        finally:
            pass

    def connect(self):
        """
        Connect server.
        连接服务器
        """
        # 发起ssh连接请求 Make a ssh connection
        ssh = self.get_connection()

        transport = ssh.get_transport()
        transport.set_keepalive(30)
        transport.use_compression(True)

        # 获取连接的隧道并设置窗口大小 Make a channel and set windows size
        global channel
        win_size = self.get_win_size()
        # self.channel = channel = ssh.invoke_shell(height=win_size[0], width=win_size[1], term='xterm')
        self.channel = channel = transport.open_session()
        channel.get_pty(term='xterm', height=win_size[0], width=win_size[1])
        channel.invoke_shell()
        try:
            signal.signal(signal.SIGWINCH, self.set_win_size)
        except:
            pass

        self.posix_shell()

        # Shutdown channel socket
        channel.close()
        ssh.close()
if __name__ == '__main__':
    P=SshTty()
    P.connect()
