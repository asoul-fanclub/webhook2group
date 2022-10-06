# webhook2group

An application for connecting `gitea` and `feishu` groups

# Config
```ini
[server]
; also :8001
HOST=192.168.200.131:8001
SECRET=
APP_ID=cli_a3b95acd8779c00b
APP_SECRET=KkHMimhQ8ELHzHd9f0C9JgXmCO1ABCDE
VERIFICATION_TOKEN=22
ENCRYPT_KEY=22
```

# Usage
1. 在[飞书开放平台](https://open.feishu.cn/)创建一个自建应用

2. 启动这个应用的机器人功能，发布应用，并将其拉入相应的群组

3. 使用飞书开放的api获取相应[群组的chat_id](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/chat-id-description)
> 当你创建应用时，你会获取到该应用的凭证`App ID`,`App Secret` 
> 
> 你可以使用凭证调用[飞书开放的api](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/chat/list)获取机器人所在群列表的chat_id
> 

4. 在gitea选择gitea的webhook，在链接处输入http://{host}:{port}/webhook/{chat_id}
> host,port: 应用部署的host与port
> chat_id: 第三步获取的群组id

# Reference
- [feishu](https://github.com/CatchZeng/feishu)
