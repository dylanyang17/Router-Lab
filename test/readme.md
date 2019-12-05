# 测试

**注意，脚本路径中使用了不少绝对路径。**

## 测试方法

每个文件夹对应一组测试。

首先运行 createNetns.sh 创建网络命名空间 netns。

接下来两个选择——运行 runBird.sh，将打开在三个 netns 中各运行一个 bird；运行 runMyTest.sh，将打开两个 bird 和一个自己实现的路由器程序。(转发相关的代码也写在runBird.sh和runMyTest.sh中了)

最后可以运行 deleteNetns.sh 删除这些网络命名空间。

## 目录

### test1

同拓扑图中仅含 R1、R2、R3 的部分。

```
netns名称:: 接口1名称: 接口1IP  [接口2名称: 接口2IP ...]
net1:: veth-1r: 192.168.3.1
net2:: veth-2l: 192.168.3.2  veth-2r: 192.168.4.1
net3:: veth-3l: 192.168.4.2
```

### test2

同拓扑图，在上面的基础上加入了两端 net0 和 net4，作为两端的机器。

```
netns名称:: 接口1名称: 接口1IP  [接口2名称: 接口2IP ...]
net0::                       veth-0r: 192.168.2.1
net1:: veth-1l: 192.168.2.2  veth-1r: 192.168.3.1
net2:: veth-2l: 192.168.3.2  veth-2r: 192.168.4.1
net3:: veth-3l: 192.168.4.2  veth-3r: 192.168.5.1
net4:: veth-4l: 192.168.5.2
```
