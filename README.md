# NuMaker-IoT-M487 测评之 Crypto

使用方法：

使用 RT-Thread Studio 创建应用，然后替换 applications 代码。

* 温馨提示

    NuMaker-IoT-M487 SDK v1.0.0 有问题，临时解决方案：将 BSP 代码到 `main` 分支的最新版本。
    升级时，务必注意只升级 Crypto 相关的二层代码即可，以免其它编译问题。    

    如果不升级，至少 SHA256 测试无法正常进行。

