# 一个没啥用的 Bot

这个 Bot 是利用 Websocket 的一个很垃圾的类似探针的 Bot

其实就是写了个一点用没有的前后端对接非得找点事干

## 关于数据安全

主端仅会传输 js 脚本给后端执行，并且加上了极其复杂的加密。

后端仅会执行 js 脚本，脚本内仅能使用运算相关的自带函数，或者映射的 fetch，yaml 序列化，psutil。

## 机器人安装方法

### 搭建

> 这里以 `Debian` 系统为例

你首先可能需要安装软件包

```bash
apt install git python3-pip -y
```

然后拉取项目

```bash
git clone https://github.com/cpploveme/SimpleTZBot.git
```

安装依赖

```bash
pip uninstall jwt

pip install -r requirements.txt
```

> 对于高版本且非虚拟环境搭建的Bot你可能需要加上 `--break-system-packages`

关于如何持久化运行这里不会详细说，你可以参考 `screen`, `pm2`, `systemd` 等方法。

### 机器人配置说明

> 关于配置文件建议参看 `readme.config.yaml` 内的详细说明。

你需要自己生成一个 RSA 密钥对，进行 base64 加密后，公钥写入后端代码的全局变量，私钥写入主端代码的全局变量。

#### 必要配置

所有配置都要填。

#### 可选配置

只有加什么后端才可选。

#### 权限相关

##### 超级管理

超级管理是最大的管理层级，它有最大的操作权限。超管可以使用 `/grant` 指令授权一个 Telegram 用户为普通管理。（`/ungrant` 来解除授权）

配置文件（数组，如果只有一个也必须有 `- ` 注意空格）：
```yaml
SuAdmin:
- 11111
- 22222
```

##### 普通管理

普通管理可以进行订阅的增添删除操作数据库的功能，也可以使用游客命令，但无法编辑配置文件。

##### 游客

游客仅能使用公共指令，这些指令不会对数据库进行修改，仅会对游客提供的订阅链接进行操作。

## 机器人使用方法

### 指令

#### 公共指令

> 这里的指令所有人都能调用

##### /help

获取帮助菜单

##### /version

获取版本信息

##### /stats

查询自身权限状态。

如果是管理员，还会展示目前后端的在线状态。

#### 普通管理指令

只能由普通管理、超级管理调用。

##### /info

查看当前后端的各种信息。

#### 超级管理指令

仅能由超级管理调用。

##### /grant <可选:id>

回复一个用户将其权限提升为管理员，也可在命令后跟着一个 id，会被写入到 `Admin`。

##### /ungrant <可选:id>

回复一个用户将其取消管理员，也可在命令后跟着一个 id，会被从 `Admin` 移除。

##### /get <路径>

对配置文件进行读取。你需要对 `config.yaml` 配置文件非常熟悉，不同级的路径需要用 `.` 分开。例如，你想获取 脚本的路径 的值：

```
/get Script
返回：
✔️ 读取成功啦 ~

键 Script
值 ./info.js
```

再例如，你想获取后端链接的超时时间：
```
/get SlaveConfig.Timeout
返回：
✔️ 读取成功啦 ~

键 SlaveConfig.Timeout
值 10
```

## 后端搭建

关于后端搭建 你需要使用 https://github.com/cpploveme/WebSocketJSExecute 仓库中的 backend.py 并安装 requirements.txt

由于其中一个依赖不维护也不 merge pr，对于 3.11 及以上的 Python 版本，你可能需要

```bash
git clone https://github.com/felixonmars/Js2Py/ -b py3.12

cd Js2Py

pip install .
```

3.13 要用 http://github.com/a-j-albert/Js2Py---supports-python-3.13

才能正常启动后端。

对于后端的启动参数请自行查看源代码或查看提示这里不再赘述。

后端不带有执行命令和读取写入文件的的功能，仅会执行主端传输的 js 代码并返回结果，除非出现鉴权漏洞。
