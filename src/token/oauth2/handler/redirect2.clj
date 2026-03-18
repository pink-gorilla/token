(ns token.oauth2.handler.redirect2
  (:require
   [ring.util.response :as response]
   [taoensso.timbre :as timbre :refer [debug info warn]]
   [token.oauth2.core :refer [exchange-code-to-token]]
   ;[token.oauth2.provider :refer [oauth2-flow-response-parse]]
   [token.oauth2.token :refer [sanitize-token]]
   [token.oauth2.store :refer [save-token]]
   [token.identity.oidc :refer [login]]))

(defn redirect-url [{:keys [scheme server-name server-port _uri] :as req} provider]
   ; {:scheme :http :server-name "localhost" :server-port 8080
   ;  :uri "/token/oauth2/start/github" :protocol "HTTP/1.1"}
   ; :headers {"host" "localhost:8080"}, 
  (info "req->url: " (select-keys req [:scheme :server-name :server-port :uri]))
  (str (name scheme) "://" server-name ":" server-port "/token/oauth2/redirect/" provider))

#_{:provider :google
   :anchor {},
   :query {:scope "email profile openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
           :prompt "consent",
           :authuser "0",
           :code "4/0ATx3LY4lnqT4ouMOPf7JIkIjFcXjnxu6Y6aL47n1J6ZcIF950eCI4WXmnI_rFXafYNuzAw"}}

#_{:iss "https://accounts.google.com",
   :code "4/0AfrIepDi5QXx2JRGoVAOtPtk7Ht5xXFo3wMZM6pM6qB7qqZaO1rLexL7C2CvBG7t5g3tng",
   :scope "email profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
   :authuser "0", :prompt "none"}

(defn handler-oauth2-redirect [{:keys [ctx params path-params] :as req}]
  (debug "oauth2/authorize-response: params: " params " path-params: " path-params)
  (let [this (:token ctx)
        {:keys [provider]} path-params
        provider-kw (keyword provider)
        {:keys [scope code state]} params
        url (redirect-url req provider-kw)]
    ;(warn "redirect this keys: " (keys this))
    (when code
      (debug "exchanging code to token for " provider  " code: " code)
      ;(info "ctx keys: " (keys ctx) "this keys: " (keys this))
      (debug "oauth2 providers: " (:providers this))
      (let [t (exchange-code-to-token this {:provider provider-kw
                                            :code code
                                            :current-url url
                                            :state state})
            _ (debug "raw token: " t)
            t (sanitize-token t)
            _ (debug "sanitized token: " t)]
        (debug "state:" state)

        (save-token this provider-kw t)

        (if (= state "identity")
          (login this {:provider provider-kw
                       :id-token (:id-token t)})
          (let [q (str "state=" (java.net.URLEncoder/encode (str state) "UTF-8")
                      "&scope=" (java.net.URLEncoder/encode (str scope) "UTF-8"))]
            (response/redirect (str "/token/oauth2/authresult?" q))))))))

