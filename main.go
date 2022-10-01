package main

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"log"
	"webhook2group/api"
	"webhook2group/config"
)

// 1. 如果access_token过期，发起请求获取access_token。path参数携带自定义机器人token，后面拼接在url中其调用webhook-robot。
// 2. 整个程序的作用是获取gitea的数据，进行解析获取email，路径中携带机器人token以及chat_group_id。获取group下的id。
//    进行缓存，然后插入@标签，调用webhook-robot向对应组发送信息

func main() {
	if err := config.InitConfig(); err != nil {
		log.Fatal(err)
	}
	api.ATReqBody = &api.AccessTokenRequest{
		AppId:     config.Config.Server.AppId,
		AppSecret: config.Config.Server.AppSecret,
	}
	config.InitTLS()
	api.UserIdDir = make(map[string]int)

	h := server.Default(
		server.WithHostPorts(config.Config.Server.Host))
	h.POST("/webhook/:chat", func(c context.Context, ctx *app.RequestContext) {
		api.StartCheck(ctx)
	})

	h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(consts.StatusOK, utils.H{"ping": "pong"})
	})

	h.Spin()
}
