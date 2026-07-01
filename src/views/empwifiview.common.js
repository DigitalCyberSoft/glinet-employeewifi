/*
 * Employee WiFi - native admin view (GL.iNet firmware 4.x, Vue 2).
 *
 * Hand-authored, NO build step. The host loader does `const c = eval(fileText)` and uses
 * the completion value as the route component, so this file is ONE expression returning a
 * Vue 2 component options object. `window.Vue` is runtime-only, so this uses render(h)
 * (no template string). GL `gl-*` / Element `el-*` components are globally registered by
 * the host and used by tag; nothing is bundled.
 *
 * Layout + CSS mirror the stock GL views (e.g. Tailscale): a `<view>-wrapper` with the
 * gl-title above a gl-card, a `.main` body, a `.desc` info line, a `<ul>`-of-`<li>` config
 * list, and centered `.btns`. Colors use GL's semantic theme variables (--divider,
 * --text-weak, --text-hint) so the page adapts to the default/classic/dark themes.
 *
 * Backend: window.$request("call", ["sid", "empwifi", <method>, <args>]) -> result object
 * (errors surface as res.err_msg).
 */
(function () {
  "use strict";

  // The session id is the Admin-Token cookie value, and it MUST be passed as params[0]:
  // this firmware (4.x on ramips) authorizes RPC from params[0] (older 4.x authorized from
  // the request header, so a literal placeholder happened to work there). Sending anything
  // but the real sid yields "Access denied", which the SPA treats as an expired session and
  // logs the admin out. Read the cookie so both firmware families authorize.
  function sid() {
    var m = document.cookie.match(/(?:^|;\s*)Admin-Token=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function req(method, args) {
    return window.$request("call", [sid(), "empwifi", method, args || {}]);
  }

  function injectStyle() {
    if (document.getElementById("empwifi-style")) return;
    var p = ".empwifi-wrapper";
    var css =
      p + "{padding:20px 0}" +
      p + " .main{max-width:635px}" +
      p + " .main .desc{display:flex;align-items:center;font-size:13px;color:var(--text-weak);margin-bottom:4px}" +
      p + " .main .desc .iconfont{font-size:14px;margin-right:14px}" +
      p + " .main .desc p{line-height:1.5;margin:0}" +
      p + " .main .empwifi-warn{display:flex;align-items:flex-start;background:var(--error-background,#fcedf2);color:var(--error,#e04c7e);border-radius:6px;padding:10px 12px;margin-bottom:12px;font-size:13px}" +
      p + " .main .empwifi-warn .iconfont{font-size:14px;margin-right:10px;margin-top:1px}" +
      p + " .main .empwifi-warn p{margin:0;line-height:1.5}" +
      p + " .main .empwifi-config{list-style:none;margin:0;padding:0}" +
      p + " .main .empwifi-config>li{min-height:50px;display:flex;align-items:center;justify-content:space-between;padding:14px 15px;border-bottom:1px solid var(--divider)}" +
      p + " .main .empwifi-config>li>div:first-child{flex:1;color:var(--text-weak);padding-right:16px}" +
      p + " .main .empwifi-config>li>div:first-child .row-desc{margin-top:3px;font-size:12px;line-height:1.5;color:var(--text-hint)}" +
      p + " .main .empwifi-config>li>div:last-child{display:flex;align-items:center;justify-content:flex-end}" +
      p + " .main .empwifi-config>li .empwifi-input{width:240px}" +
      p + " .btns{display:flex;justify-content:center;align-items:center;margin-top:20px}" +
      p + " .btns .btn-item{min-width:124px;height:36px}";
    var s = document.createElement("style");
    s.id = "empwifi-style";
    s.textContent = css;
    document.head.appendChild(s);
  }

  return {
    name: "empwifiview",

    data: function () {
      return {
        loading: true,
        saving: false,
        cfg: {
          no_password: false,
          has_password: false,
          camouflage_default: true,
          camouflage_supported: false
        },
        newPassword: ""
      };
    },

    created: function () {
      injectStyle();
      this.load();
    },

    methods: {
      load: function () {
        var self = this;
        self.loading = true;
        req("admin_get_config").then(function (res) {
          if (res && res.err_msg) self.$message.error(res.err_msg);
          else if (res) self.cfg = res;
          self.loading = false;
        }).catch(function () {
          self.loading = false;
          self.$message.error(self.$t("empwifi.load_failed"));
        });
      },

      save: function () {
        var self = this;
        if (!self.cfg.no_password && !self.cfg.has_password && !self.newPassword) {
          self.$message.error(self.$t("empwifi.err_need_password"));
          return;
        }
        if (self.newPassword && self.newPassword.length < 8) {
          self.$message.error(self.$t("empwifi.password_too_short"));
          return;
        }
        self.saving = true;
        var args = {
          no_password: !!self.cfg.no_password,
          camouflage_default: !!self.cfg.camouflage_default
        };
        if (self.newPassword) args.emp_password = self.newPassword;

        req("admin_set_config", args).then(function (res) {
          self.saving = false;
          if (res && res.err_msg) { self.$message.error(res.err_msg); return; }
          if (res) self.cfg = res;
          self.newPassword = "";
          self.$message.success(self.$t("empwifi.saved"));
        }).catch(function () {
          self.saving = false;
          self.$message.error(self.$t("empwifi.save_failed"));
        });
      }
    },

    render: function (h) {
      var self = this;
      var t = function (k) { return self.$t(k); };

      // a config <li>: label (+optional sub-desc) on the left, control on the right
      function row(title, desc, control) {
        var left = [h("div", { staticClass: "row-title" }, [title])];
        if (desc) left.push(h("div", { staticClass: "row-desc" }, [desc]));
        return h("li", [h("div", left), h("div", [control])]);
      }

      var rows = [
        row(t("empwifi.no_password"), t("empwifi.no_password_desc"),
          h("gl-switch", {
            attrs: { size: "small" },
            model: {
              value: self.cfg.no_password,
              callback: function (v) { self.$set(self.cfg, "no_password", v); }
            }
          }))
      ];

      if (!self.cfg.no_password) {
        rows.push(row(
          t("empwifi.password"),
          self.cfg.has_password ? t("empwifi.password_set_desc") : t("empwifi.password_unset_desc"),
          h("el-input", {
            staticClass: "empwifi-input",
            attrs: {
              type: "password",
              clearable: true,
              "show-password": true,
              placeholder: self.cfg.has_password ? t("empwifi.password_keep") : t("empwifi.password_ph")
            },
            model: {
              value: self.newPassword,
              callback: function (v) { self.newPassword = v; }
            }
          })));
      }

      if (self.cfg.camouflage_supported) {
        rows.push(row(t("empwifi.camouflage"), t("empwifi.camouflage_desc"),
          h("gl-switch", {
            attrs: { size: "small" },
            model: {
              value: self.cfg.camouflage_default,
              callback: function (v) { self.$set(self.cfg, "camouflage_default", v); }
            }
          })));
      }

      var body = [
        h("div", { staticClass: "desc" }, [
          h("span", { staticClass: "iconfont icon-info" }),
          h("p", [t("empwifi.intro")])
        ])
      ];
      // Loud warning: no-password mode lets any device on this router repoint the uplink.
      if (self.cfg.no_password) {
        body.push(h("div", { staticClass: "empwifi-warn" }, [
          h("span", { staticClass: "iconfont icon-info" }),
          h("p", [t("empwifi.no_password_warning")])
        ]));
      }
      body.push(h("ul", { staticClass: "empwifi-config" }, rows));
      body.push(h("div", { staticClass: "btns" }, [
        h("gl-button", {
          staticClass: "btn-item",
          attrs: { type: "primary", disabled: self.saving },
          on: { click: self.save }
        }, [t("core.apply")])
      ]));

      var main = self.loading
        ? [h("div", { staticClass: "desc" }, [h("p", [t("empwifi.loading")])])]
        : body;

      return h("div", { staticClass: "empwifi-wrapper" }, [
        h("gl-title", { attrs: { title: t("empwifi.title") } }),
        h("gl-card", [h("div", { staticClass: "main" }, main)])
      ]);
    }
  };
})()
