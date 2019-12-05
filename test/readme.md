# 测试方法

首先运行 createNetnsX.sh 创建网络命名空间 netns。

接下来两个选择——运行 runBird.sh，将打开在三个 netns 中各运行一个 bird；运行 runMyTest.sh，将打开两个 bird 和一个自己实现的路由器程序。

最后可以运行 deleteNetnsX.sh 删除这些网络命名空间。
