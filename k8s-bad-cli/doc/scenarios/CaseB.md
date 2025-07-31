# CaseB: Hunting


> En una actividad de Hunting el atacante tiene acceso al nodo ....


<img src="../../assets/privilegeEscalation.webp" align="center" width="50%" height="50%"/>


### Comportamiento: Ejecutar escaneo de red

*Regla: Launch suspicious network tool in container*

    PENDING


### Comportamiento: Intento de directory traversal

*Regla: Directory traversal monitored file read*

    {"hostname":"falcox33-falco-obsec-dvlm2","output":"15:15:42.386811464: Warning Read monitored file via directory traversal (username=<NA> useruid=1001 user_loginuid=-1 program=cat exe=/usr/bin/cat command=cat ../../../../etc/passwd pid=12321 parent=falco-workshop file=/etc/passwd fileraw=../../../../etc/passwd parent=falco-workshop gparent=go container_id=c78228991987 image=docker.io/diegoall1990/falco-workshop returncode=SUCCESS cwd=/home/falcox/ Custom_Tags=IRT_Alert) k8s.ns=falco-custom-lab k8s.pod=vistima container=c78228991987","priority":"Warning","rule":"Directory traversal monitored file read","source":"syscall","tags":["IRT_Alert","filesystem","mitre_credential_access","mitre_discovery","mitre_exfiltration"],"time":"2024-08-15T15:15:42.386811464Z", "output_fields": {"container.id":"c78228991987","container.image.repository":"docker.io/diegoall1990/falco-workshop","evt.res":"SUCCESS","evt.time":1723734942386811464,"fd.name":"/etc/passwd","fd.nameraw":"../../../../etc/passwd","k8s.ns.name":"falco-custom-lab","k8s.pod.name":"vistima","proc.aname[2]":"go","proc.cmdline":"cat ../../../../etc/passwd","proc.cwd":"/home/falcox/","proc.exepath":"/usr/bin/cat","proc.name":"cat","proc.pid":12321,"proc.pname":"falco-workshop","user.loginuid":-1,"user.name":"<NA>","user.uid":1001}}



### Comportamiento: loren ipsum

*Regla: rule*

    {"hostname":"falcox33-falco-obsec-dvlm2","output":"15:16:24.949370309: Warning Mount was executed inside a privileged container (user=<NA> user_loginuid=-1 command=mount -o bind /bin/sh /bin/mount pid=12691 k8s.ns=falco-custom-lab k8s.pod=vistima container=c78228991987 image=docker.io/diegoall1990/falco-workshop:0.0.1)","priority":"Warning","rule":"Mount Launched in Privileged Container","source":"syscall","tags":["cis","container","mitre_lateral_movement"],"time":"2024-08-15T15:16:24.949370309Z", "output_fields": {"container.id":"c78228991987","container.image.repository":"docker.io/diegoall1990/falco-workshop","container.image.tag":"0.0.1","evt.time":1723734984949370309,"k8s.ns.name":"falco-custom-lab","k8s.pod.name":"vistima","proc.cmdline":"mount -o bind /bin/sh /bin/mount","proc.pid":12691,"user.loginuid":-1,"user.name":"<NA>"}}



### Comportamiento: loren ipsum

*Regla: rule*

    {"hostname":"falcox33-falco-obsec-dvlm2","output":"15:16:30.960568967: Critical Detect Polkit pkexec Local Privilege Escalation Exploit (CVE-2021-4034) (user=<NA> uid=-1 command=pkexec  pid=12742 args= Custom_Tags=IRT_Alert) k8s.ns=falco-custom-lab k8s.pod=vistima container=c78228991987","priority":"Critical","rule":"Polkit Local Privilege Escalation Vulnerability (CVE-2021-4034)","source":"syscall","tags":["IRT_Alert","mitre_privilege_escalation","process"],"time":"2024-08-15T15:16:30.960568967Z", "output_fields": {"container.id":"c78228991987","evt.time":1723734990960568967,"k8s.ns.name":"falco-custom-lab","k8s.pod.name":"vistima","proc.args":"","proc.cmdline":"pkexec ","proc.pid":12742,"user.loginname":"<NA>","user.loginuid":-1}}


### Comportamiento: loren ipsum

*Regla: rule*


    {"hostname":"falcox33-falco-obsec-dvlm2","output":"15:16:33.972637069: Critical Detect Sudo Privilege Escalation Exploit (CVE-2021-3156) (user=<NA> parent=falco-workshop cmdline=sudoedit -s \\ perl -e print \"A\" x 20 pid=12779 k8s.ns=falco-custom-lab k8s.pod=vistima container=c78228991987 Custom_Tags=IRT_Alert)","priority":"Critical","rule":"Sudo Potential Privilege Escalation","source":"syscall","tags":["IRT_Alert","filesystem","mitre_privilege_escalation"],"time":"2024-08-15T15:16:33.972637069Z", "output_fields": {"container.id":"c78228991987","evt.time":1723734993972637069,"k8s.ns.name":"falco-custom-lab","k8s.pod.name":"vistima","proc.cmdline":"sudoedit -s \\ perl -e print \"A\" x 20","proc.pid":12779,"proc.pname":"falco-workshop","user.name":"<NA>"}}
