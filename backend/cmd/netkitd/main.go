// netkitd 是昱弘网通 NetKit 的后端。
//
// 两种跑法，**同一套能力**（见 docs/设计.md「AI 接口」）：
//
//	netkitd            起本地 HTTP API，给 Electron 界面和脚本用
//	netkitd -mcp       在 stdin/stdout 上跑 MCP，给 AI 用
//
// ★ 后者只是前者的一层薄封装，不是另一套实现。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"net.yuhox.com/netkit/internal/api"
	"net.yuhox.com/netkit/internal/mcp"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
	"net.yuhox.com/netkit/internal/tools"
)

// Version 由编译台注入；本地构建就是 dev。
var Version = "dev"

func main() {
	var (
		asMCP      = flag.Bool("mcp", false, "在 stdin/stdout 上跑 MCP 服务（给 AI 调用）")
		addr       = flag.String("addr", "127.0.0.1:0", "HTTP API 监听地址。非回环地址必须同时给 -token")
		token      = flag.String("token", "", "调用令牌。监听非回环地址时必填")
		approveURL = flag.String("approve-url", "",
			"批准端点（界面开的）。★ 不给 = 没有批准渠道 = 改系统的工具一律拒绝执行")
		journalPath = flag.String("journal", "", "改动账本路径。默认放用户配置目录")
		mutations   = flag.Bool("mutations", false,
			"启用会改系统的工具。★ 一期不要开：改系统的工具必须等「先登记后执行、能还原」机制落地")
	)
	flag.Parse()

	reg := ots.NewRegistry(*mutations)

	// ★ 改系统的功能必须先有账本（先登记后执行、崩了能还原）。
	//   账本开不了就**不启用** mutate —— 而不是"没账本也照改"。
	jp := *journalPath
	if jp == "" {
		dir, err := os.UserConfigDir()
		if err == nil {
			jp = filepath.Join(dir, "yuhox-netkit", "changes.json")
		}
	}
	if jp != "" {
		if j, err := state.Open(jp); err != nil {
			fmt.Fprintln(os.Stderr, "打不开改动账本，改系统的功能将不可用：", err)
		} else {
			tools.SetJournal(j)
			tools.RestoreOnStart(slog.Default())
		}
	}
	if *approveURL != "" {
		reg.SetApprover(&api.HTTPApprover{URL: *approveURL})
	}

	tools.Register(reg)

	if *asMCP {
		// ★ MCP 走 stdio，stdout 是协议通道 —— 日志**必须**走 stderr，
		//   往 stdout 打一行日志就会把协议流冲坏，而且表现成客户端莫名其妙地断开。
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
		srv := mcp.New(reg, "昱弘网通 NetKit", Version)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := srv.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "MCP 服务出错：", err)
			os.Exit(1)
		}
		return
	}

	srv, err := api.New(reg, api.Config{Addr: *addr, Token: *token})
	if err != nil {
		fmt.Fprintln(os.Stderr, "起不来：", err)
		os.Exit(1)
	}
	got, err := srv.Listen()
	if err != nil {
		fmt.Fprintln(os.Stderr, "起不来：", err)
		os.Exit(1)
	}
	slog.Info("NetKit 后端已启动",
		"addr", got, "spec", "OTS "+ots.Version, "conformance", reg.Conformance(),
		"tools", len(reg.Visible()), "mutations", *mutations)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	_ = srv.Close()
}
