package main

import (
	"context"
	"fmt"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"log"
	"sync"
	"webhook2group/api"
	"webhook2group/config"
)

// 1. 如果access_token过期，发起请求获取access_token。其中webhook请求path参数携带chat_id
// 2. 整个程序的作用是获取gitea的数据，进行解析获取email，路径中携带chat_id。根据email获取group下的id，结合@群组成员发送消息

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// 初始化配置文件
	if err := config.InitConfig(); err != nil {
		log.Fatal(err)
	}
	// 设定自建应用信息
	api.ATReqBody = &api.AccessTokenRequest{
		AppId:     config.Config.Server.AppId,
		AppSecret: config.Config.Server.AppSecret,
	}
	// 缓存用户email-id
	api.UserIdDir = sync.Map{}
	// 启动webserver
	h := server.Default(
		server.WithHostPorts(config.Config.Server.Host))
	// webhook api
	h.POST("/webhook/:chat", func(c context.Context, ctx *app.RequestContext) {
		go api.StartCheck(ctx)
	})

	h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(consts.StatusOK, utils.H{"ping": "pong"})
	})

	h.Spin()
}
