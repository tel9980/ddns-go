package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

//go:embed login.html
var loginEmbedFile embed.FS

// CookieName cookie name
const cookieName = "token"

// CookieInSystem only one cookie
var cookieInSystem = &http.Cookie{}

// 服务启动时间
var startTime = time.Now()

// 保存限制时间
const saveLimit = time.Duration(30) * time.Minute

// Login login page
func Login(writer http.ResponseWriter, request *http.Request) {
	tmpl, err := template.ParseFS(loginEmbedFile, "login.html")
	if err != nil {
		fmt.Println("Error happened..")
		fmt.Println(err)
		return
	}

	conf, _ := config.GetConfigCached()

	csrfToken := ensureCsrfCookie(writer, request)

	err = tmpl.Execute(writer, struct {
		EmptyUser bool   // 未填写用户名和密码
		Lang      string // 当前后端语言
		CsrfToken string // CSRF token for the login form
	}{
		EmptyUser: conf.Username == "" && conf.Password == "",
		Lang:      conf.Lang,
		CsrfToken: csrfToken,
	})
	if err != nil {
		fmt.Println("Error happened..")
		fmt.Println(err)
	}
}

// LoginFunc login func
func LoginFunc(w http.ResponseWriter, r *http.Request) {
	conf, _ := config.GetConfigCached()
	util.InitLogLang(conf.Lang)

	requestIP := r.RemoteAddr
	if loginLocked(requestIP) {
		util.Log("%q 登录失败次数过多，已锁定", requestIP)
		returnError(w, util.LogStr("登录失败次数过多，请稍后再试"))
		return
	}

	// CSRF check for the login endpoint
	if !validCsrf(r) {
		returnError(w, util.LogStr("CSRF 验证失败，请刷新页面重试"))
		return
	}

	// 从请求中读取 JSON 数据
	var data struct {
		Username string `json:"Username"`
		Password string `json:"Password"`
	}

	err := json.NewDecoder(r.Body).Decode(&data)

	if err != nil {
		returnError(w, err.Error())
		return
	}

	// 用户名密码不能为空
	if data.Username == "" || data.Password == "" {
		returnError(w, util.LogStr("必须输入用户名/密码"))
		return
	}


	// 初始化用户名密码。新安装默认禁止公网访问，不再根据可伪造的
	// Referer 请求头放宽限制；如需公网访问请手动修改配置。
	if conf.Username == "" && conf.Password == "" {
		if time.Since(startTime) > saveLimit {
			returnError(w, util.LogStr("需在 %s 之前完成用户名密码设置,请重启ddns-go", startTime.Add(saveLimit).Format("2006-01-02 15:04:05")))
			return
		}

		conf.NotAllowWanAccess = true

		conf.Username = data.Username
		hashedPwd, err := conf.CheckPassword(data.Password)
		if err != nil {
			returnError(w, err.Error())
			return
		}
		conf.Password = hashedPwd
		conf.SaveConfig()
	}

	// 登录
	if data.Username == conf.Username && util.PasswordOK(conf.Password, data.Password) {
		// 设置cookie过期时间为1天
		timeoutDays := 1
		if conf.NotAllowWanAccess {
			// 内网访问cookie过期时间为30天
			timeoutDays = 30
		}

		// 覆盖cookie
		cookieInSystem = &http.Cookie{
			Name:     cookieName,
			Value:    util.GenerateToken(data.Username), // 生成token
			Path:     "/",
			Expires:  time.Now().AddDate(0, 0, timeoutDays), // 设置过期时间
			HttpOnly: true,
		}
		// 写入cookie
		http.SetCookie(w, cookieInSystem)

		util.Log("%q 登录成功", requestIP)
		resetLogin(requestIP)

		returnOK(w, util.LogStr("登录成功"), cookieInSystem.Value)
		return
	}

	recordLoginFailure(requestIP)
	util.Log("%q 帐号密码不正确", requestIP)
	returnError(w, util.LogStr("用户名或密码错误"))
}
