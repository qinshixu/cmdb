#encoding=utf-8
# Create your views here.
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import render_to_response,render
from django.template import Template,loader,RequestContext
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.contrib import auth
from django import  forms
from app.models import *
from app.backend.saltapi  import SaltAPI
from app.backend.asset_info import get_server_asset_info
import MySQLdb as mysql,datetime
import  ConfigParser,sys,json,os,time,pickle
import salt.client

db = mysql.connect(user="root", passwd="123456", db="monitor", charset="utf8")
db.autocommit(True)
c = db.cursor()

client=salt.client.LocalClient()

def saltstack():
    config = ConfigParser.ConfigParser()
    config.read("/web/CMDB/app/backend/config.ini")
    url = config.get("saltstack","url")
    user = config.get("saltstack","user")
    passwd = config.get("saltstack","pass")
    device = config.get("network","device")
    result_api={'url':url,'user':user,'passwd':passwd,'device':device}
    return result_api
def wirte_track_mark(num):
    f = open("/web/CMDB/app/backend/track_num.conf",'w')
    try:
        f.write(num)
    finally:
        f.close()
    return "ok"
def read_track_mark():
    f = open("/web/CMDB/app/backend/track_num.conf")
    try:
	num = f.read()
    finally:
	f.close()
    return num
def date_result(data):
    timeArray = time.strptime(data, "%Y-%m-%d %H:%M:%S")
    timeStamp = int(time.mktime(timeArray)) - 50400
    return timeStamp

@login_required
def index(request):
    total_idc =Idc.objects.aggregate(Count('idc_name'))
    #for k,v in total_idc.items():
    #    print k,v
    idc_num = total_idc["idc_name__count"]
    total_host = HostList.objects.aggregate(Count('hostname'))
    host_num = total_host["hostname__count"]
    return render_to_response("index.html",locals())
def get_clinet_ip(request):
    try:
        real_ip = request.MEAT['HTTP_X_FORWARDED_FOR']
        regip = real_ip.split(",")[0]
    except:
        regip = request.META['REMOTE_ADDR']
    return regip
def login(request):
    return render_to_response("login.html")
def authin(request):
    username = request.POST.get('username','')
    password = request.POST.get('password','')
    real_ip = get_clinet_ip(request)
    if username and password is not  None:
        total_idc =Idc.objects.aggregate(Count('idc_name'))
        idc_num = total_idc["idc_name__count"]
        user = auth.authenticate(username=username,password=password)
        total_host = HostList.objects.aggregate(Count('hostname'))
        host_num = total_host["hostname__count"]
        print request.user,user,total_idc,idc_num,host_num
        if user is not None:
            auth.login(request,user)
            P = Login_Record(name=username,ip=real_ip,status=1)
            P.save()
            return  render_to_response('index.html',{'login_user':request.user,'idc_num':idc_num,'host_num':host_num})
        else:
            P = Login_Record(name=username,ip=real_ip)
            P.save()
            return render_to_response('login.html',{'login_err':'Wrong username or password!'})
    else:
        P = Login_Record(name=username,ip=real_ip)
        P.save()
        return render_to_response('login.html',{'login_err':'Please input username or password!'})
@login_required
def idc(request):
    all_idc = Idc.objects.all()
    return render_to_response("idc.html",locals())
@login_required
def addidc(request):
    nameInput = request.GET['nameInput']
    msgInput = request.GET['msgInput']
    all_idc = Idc.objects.all()
    idc_name_list=[]
    for i in all_idc:
        idc_name_list.append(i.idc_name)
    print idc_name_list
    if nameInput in idc_name_list:
        return HttpResponse('exist')
    else:
        idc_add = Idc(idc_name=nameInput,remark=msgInput)
        idc_add.save()
        return HttpResponse('ok')

@login_required
def idc_delete(request,id=None):
    if request.method == 'GET':
        id = request.GET.get('id')
        Idc.objects.filter(id=id).delete()
        return HttpResponseRedirect('/idc/')
@login_required
def idc_update(request):
    if request.method == 'POST':
        remark=request.POST.get('msgInput')
        name=request.POST.get('id')
        print name,remark
        a=Idc.objects.get(idc_name=name)
        a.remark=remark
        a.save()
        return HttpResponseRedirect('/idc/')


@login_required
def mac(request):
    all_host = HostList.objects.all()
    all_idc = Idc.objects.all()
    return render_to_response("mac.html",locals())
@login_required
def addmac(request):
    if request.method == 'GET':
        name = request.GET['name']
        ip = request.GET['ip']
        idc_name = request.GET['idc_name']
        service = request.GET['service']
        idc_bh = request.GET['idc_jg']
        mac_add = HostList(ip=ip,hostname=name,application=service,idc_name=idc_name,bianhao=idc_bh)
        mac_add.save()
        return HttpResponse('ok')
@login_required
def mac_delete(request,id=None):
    if request.method == 'GET':
        id = request.GET.get('id')
        HostList.objects.filter(id=id).delete()
        return HttpResponseRedirect('/mac/')
@login_required
def mac_edit(request,id=None):
    if request.method == 'GET':
	id = request.GET.get('id')
	all_idc = Idc.objects.all()
        all_host=HostList.objects.filter(id=id)
	return render_to_response("mac_edit.html",locals())
@login_required
def macresult(request):
    if request.method =='GET':
        id = request.GET['id']
        ip = request.GET['ip']
        name = request.GET['name']
        idc_name = request.GET['idc_name']
        service = request.GET['service']
        idc_bh = request.GET['idc_jg']
        try:
            mac_update = HostList.objects.filter(id=id).update(ip=ip,hostname=name,application=service,idc_name=idc_name,bianhao=idc_bh)
            mac_update.save()
	except:
	    print "get exception"
	finally:
            return HttpResponse('ok')



@login_required
def download(request):
    if request.method == 'GET':
	all_host = HostList.objects.all()
    return render_to_response('download.html',locals())

@login_required
def download_result(request):
    if request.method =='POST':
        hostname = request.POST.get('hostname')
        filepath = request.POST.get('dir')
        print hostname,filepath
#        cmd='salt %s cp.push %s' %(hostname,filepath)
        ret=client.cmd(hostname,'cp.push',[filepath])
        print ret
#        ret=os.popen(cmd).readlines()
        if ret[hostname]:
            salt_minior_dir='/var/cache/salt/master/minions/u1/files'
            fullpath=salt_minior_dir+filepath
            f=open(fullpath)
            data=f.read()
            filename = fullpath.split('/')[-1]
            response = HttpResponse(data,mimetype='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename=%s' %filename
            return response
        else:
            all_host = HostList.objects.all()
            ret='File not exist or host connect failed'
            return render_to_response('download.html',locals())


class UploadForm(forms.Form):
    headImg = forms.FileField()
@login_required
def file(request):
#    if request.method == 'POST':
    all_host = HostList.objects.all()
    all_file = Upload.objects.all()
    uf = UploadForm(request.POST,request.FILES)
    if uf.is_valid():
        headImg = uf.cleaned_data['headImg']
        user = Upload()
        user.headImg = headImg
        user.save()
    return render_to_response('file.html',locals())
@login_required
def file_result(request):
    hostname = request.GET.get('hostname')
    salt_file = request.GET.get('file')
    mini_dest = request.GET.get('dir')
    ret=client.cmd(hostname,'cp.get_file',['salt:/'+salt_file,mini_dest])
    print ret
    if ret[hostname]:
        if 'exception' in ret[hostname]:
            result = {'mes':'推送目录填写错误'}
            return HttpResponse(json.dumps(result))
        if  mini_dest in ret[hostname]:
            print '上传成功'
            result = {'mes':"推送成功"}
            return HttpResponse(json.dumps(result))
    else:
        print '上传失败'
        mes='上传至主机%s失败' % str(hostname)
        result = {'mes':mes}
        return HttpResponse(json.dumps(result))
@login_required
def del_upload_file(request):
    Upload.objects.all().delete()
    Path='/web/CMDB/upload/'
    if os.path.exists(Path):
        files=os.listdir(Path)
        for i in files:
            os.remove(Path+i)
    return HttpResponse('ok')
@login_required
def groupfile(request):
#    if request.method == 'POST':
    all_group = Group.objects.all()
    all_file = Upload.objects.all()
    uf = UploadForm(request.POST,request.FILES)
    if uf.is_valid():
        headImg = uf.cleaned_data['headImg']
        user = Upload()
        user.headImg = headImg
        user.save()
    return render_to_response('groupfile.html',locals())
#    else:
#        uf = UserForm()
#        return render_to_response('file.html',{'uf':uf})
@login_required
def groupfile_result(request):
    if request.method == 'GET':
	import sys
	reload(sys)
	sys.setdefaultencoding( "utf-8" )
	g_name = request.GET.get('g_name')
	file = request.GET.get('file')
	dir = request.GET.get('dir')
    print g_name,file,dir
    GroupList = Group.objects.all()
    list_coun = []
    project_success = []
    project_fail = []
    salt_return.objects.filter().delete()
    for groupname in GroupList:
            if groupname.name in g_name:
                print "slected group:",groupname.name
                for selected_ip in HostList.objects.filter(group__name = groupname.name):
                    hosts = HostList.objects.filter(ip=selected_ip.ip)
                    for host in hosts:
                        key_id = host.hostname
                        cmd = "salt %s cp.get_file salt:/%s %s"  %(key_id,file,dir)
                        ret=client.cmd(key_id,'cp.get_file',['salt:/'+file,dir])
                        print ret
                        if dir in ret[key_id]:
                            print '上传成功'
                            b=salt_return(jid=cmd,host=key_id,success='1',result=ret)
                            b.save()
                            list_coun.append(host)
                        else:
                            b=salt_return(jid=cmd,host=key_id,success='0',result=ret)
                            b.save()
                            print '上传失败'
                            list_coun.append(host)
                num = len(list_coun)
                print num
                wirte_track_mark(str(num))
                all_result = salt_return.objects.all()[0:num]
                for projects in all_result:
                    print projects.success
                    if projects.success == '1':
                        project_success.append(projects.success)
                    else:
                        project_fail.append(projects.success)
                success_num = len(project_success)
                fail_num = len(project_fail)
                result = {'success':success_num,'fail':fail_num}
                return HttpResponse(json.dumps(result))

@login_required
def command(request):
    if request.method == 'GET':
	all_host = HostList.objects.all()
    return render_to_response("command.html",locals())
@login_required
def command_result(request):
    if request.method == 'GET':
        ret_api = saltstack()
        key_id = request.GET.get('hostname')
        command = request.GET.get('command')
        print key_id,command
#        host = HostList.objects.filter(ip=ip)
        sapi = SaltAPI(url=ret_api["url"],username=ret_api["user"],password=ret_api["passwd"])
        try:
            ret = sapi.remote_execution(key_id,'cmd.run',command)
            for i in range(len(ret)):
                ret=ret[i][key_id]
	        r_data = {'host':key_id,'ret':ret}
            data = json.dumps(r_data)
            return HttpResponse(data)
        except:
            print '123'
            return HttpResponse('ok')

@login_required
def command_group(request):
    if request.method == 'GET':
	all_group = Group.objects.all()
    return render_to_response("command_group.html",locals())
def command_group_result(request):
    if request.method == 'GET':
	ret_api = saltstack()
        g_name = request.GET.get('g_name')
        command = request.GET.get('command')
        selectIps = []
	list_coun = []
        project_success = []
	project_fail = []
        GroupList = Group.objects.all()
        salt_return.objects.filter().delete()
        for groupname in GroupList:
            if groupname.name in g_name:
                print "slected group:",groupname.name
                for selected_ip in HostList.objects.filter(group__name = groupname.name):
                    host = HostList.objects.filter(ip=selected_ip.ip)
                    for host in host:
                        key_id = host.hostname
                        sapi = SaltAPI(url=ret_api["url"],username=ret_api["user"],password=ret_api["passwd"])
                        try:
                            ret = sapi.remote_execution(key_id,'cmd.run',command)
		            list_coun.append(host)
                            ret=ret[0][key_id]
                            b=salt_return(jid=command,host=key_id,success='1',result=ret)
                            b.save()
                        except:
                            print "Connect %s failed" % key_id
                            b=salt_return(jid=command,host=key_id,success='0',result='failed')
                            b.save()
		num = len(list_coun)
	        wirte_track_mark(str(num))
		all_result = salt_return.objects.all()[0:num]
		for projects in all_result:
		    project=projects.success
		    if project == '1':
			project_success.append(project)
		    else:
			project_fail.append(project)
		success_num = len(project_success)
		fail_num = len(project_fail)
		result = {'success':success_num,'fail':fail_num}
        return HttpResponse(json.dumps(result))
@login_required
def check_result(request):
    num = int(read_track_mark())
    all_result = salt_return.objects.all().order_by("-id")[0:num]
    return render_to_response("check_result.html",locals())
@login_required
def job(request):
    return render_to_response("job.html")
@login_required
def asset(request):
    all_asset = ServerAsset.objects.all()
    return render_to_response("asset.html",locals())
@login_required
def asset_auto(request):
    all_host = HostList.objects.all()
    return render_to_response("asset_auto.html",locals())
@login_required
def asset_auto_result(request):
     if request.method == 'GET':
	ret_api = saltstack()
	try:
	    client = request.GET.get('client')
            result = get_server_asset_info(client,ret_api["url"],ret_api["user"],ret_api["passwd"],ret_api["device"])
            result_data = ServerAsset()
            result_data.manufacturer = result[0][0]
            result_data.productname = result[0][1]
            result_data.service_tag = result[0][2]
            result_data.cpu_model = result[0][3]
            result_data.cpu_nums = result[0][4]
            result_data.cpu_groups = result[0][5]
            result_data.mem = result[0][6]
            result_data.disk = result[0][7]
            result_data.hostname = result[0][8]
            result_data.ip = result[0][9][0]
            result_data.os = result[0][10]
            result_data.save()
	except:
	    print "print check you asset"
	    return HttpResponse('ok')
	else:
            data = json.dumps(result)
            return HttpResponse(data)
@login_required
def asset_delete(request,id=None):
    if request.method == 'GET':
	id = request.GET.get('id')
        ServerAsset.objects.filter(id=id).delete()
	return HttpResponseRedirect('/asset/')
@login_required
def group(request):
    all_group = Group.objects.all()
    return render_to_response("group.html",locals())
@login_required
def group_result(request):
    if request.method == 'GET':
	group = request.GET.get('g_name')
	data = Group()
	data.name = group
	data.save()
	return HttpResponse("ok")
@login_required
def group_delete(request,id=None):
    id = request.GET['id']
    group_id = Group.objects.get(id=id)
    all_ip=group_id.hostlist_set.all()
    if all_ip:
        return HttpResponse('exist')
    else:
        Group.objects.filter(id=id).delete()
        return HttpResponse('ok')
@login_required
def group_manage(request,id=None):
    if request.method == 'GET':
	id = request.GET.get('id')
	group_name = Group.objects.get(id=id)
 	all_ip = group_name.hostlist_set.all()
	all_host = HostList.objects.all()
    return render_to_response("group_manage.html",locals())
@login_required
def group_manage_delete(request,group_name=None,ip=None):
#    if request.method == 'GET':
#	group_name = request.GET.get('group_name')
#	ip = request.GET.get('ip')
        group_name = request.GET['group_name']
        ip = request.GET['ip']
        try:
	        all_group = Group.objects.filter(name=group_name)
	        all_host = HostList.objects.filter(ip=ip)
	        for group in all_group:
	            group_id= group.id
	        for host in all_host:
	            host_id= host.id
                h = HostList.objects.get(id=host_id)
                g = Group.objects.get(id=group_id)
	        h.group.remove(g)
	        return HttpResponse('ok')
        except:
            return HttpResponse('false')
@login_required
def addgroup_host(request):
    if request.method == 'GET':
	group = request.GET.get('nameInput')
	ip = request.GET.get('hostInput')
	all_group = Group.objects.filter(name=group)
        all_host = HostList.objects.filter(ip=ip)
	for group in all_group:
            group_id= group.id
        try:
            for host in all_host:
                host_id= host.id
            h = HostList.objects.get(id=host.id)
            g = Group.objects.get(id=group_id)
	    h.group.add(g)
	    return HttpResponse('ok')
        except:
            return HttpResponse('false')
@login_required
def oprationfile(request):
    if request.method == 'GET':
        all_host = HostList.objects.all()
        return render_to_response('opration_file.html',locals())
def oprationfile_result(request):
    import shutil
    all_host = HostList.objects.all()
    hostname = request.POST.get('hostInput')
    path = request.POST.get('filepath')
    salt_minior_dir='/var/cache/salt/master/minions/u1/files'
    salt_path=salt_minior_dir+path
    print path,hostname
    if os.path.exists(salt_path):
        shutil.rmtree(salt_path)
    client.cmd(hostname,'cp.push_dir',[path])
#    cmd='salt %s cp.push_dir %s' %(hostname,path)
#    ret=os.popen(cmd).readlines()
    if path and '/' in path[-1]:
        files={}
        dirs=os.listdir(salt_path)
        for f in dirs:
            fileList=[]
            filePath=salt_path+f
            if os.path.isfile(filePath):
                '''
                Str_UpdateTime=datetime.datetime.fromtimestamp(os.path.getmtime(filePath))
                FileUpdateTime=Str_UpdateTime.strftime('%Y-%m-%d %H:%M:%S')
                files[f]=FileUpdateTime
                '''
                FileSize=round(os.path.getsize(filePath)/1000.0,1)
                files[f]=FileSize

        print files
        return render_to_response('opration_file.html',locals())
    else:
        mes='*请填写正确的文件路径*'
        return render_to_response('opration_file.html',locals())
@login_required
def oprationfile_check(request):
    hostname=request.GET.get('hostname')
    path=request.GET.get('path')
    filename=request.GET.get('filename')
    print hostname,path,filename
    salt_minior_dir='/var/cache/salt/master/minions/u1/files'
    filepath=path+filename
    salt_filepath=salt_minior_dir+path+filename
    print filepath
    f=open(salt_filepath)
    content=f.read()
    f.close()
    print content
    r_data={'hostname':hostname,'filepath':filepath,'content':content}
    data=json.dumps(r_data)
    return HttpResponse(data)
@login_required
def oprationfile_update(request):
    hostname=request.POST.get('hostname')
    filepath=request.POST.get('filepath')
    content=request.POST.get('content')
    content=content.encode("utf-8")
    salt_minior_dir='/var/cache/salt/master/minions/u1/files'
    salt_filepath=salt_minior_dir+filepath
    path=os.path.dirname(filepath)+'/'
    f=open(salt_filepath,'w')
    f.write(content)
    f.close()
    client.cmd(hostname,'cp.get_file',['salt:/'+salt_filepath,filepath])
#    cmd='salt %s cp.get_file  salt:/%s %s' % (hostname,salt_filepath,filepath)
#    ret=os.popen(cmd).readlines()
    return render_to_response('opration_update.html',locals())
@login_required
def service_result(request):
    hostname=str(request.GET.get('h'))
    cmd_flag=request.GET.get('cmd')
    all_host = HostList.objects.all()
    print hostname,cmd_flag
    if hostname and cmd_flag:
        if str(cmd_flag)=='1':
            cmd="/root/deploy/deploy.sh -r"
        elif str(cmd_flag)=='2':
            cmd="/root/deploy/deploy.sh -u"
        ret=client.cmd(hostname,'cmd.run',[cmd])
        if ret:
            ret=ret[hostname]
            print ret
            return render_to_response('service_result.html',locals())
        else:
            ret='Connect host  Failed!'
            return render_to_response('service_result.html',locals())
    else:
        return render_to_response('service.html',locals())
