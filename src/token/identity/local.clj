(ns token.identity.local
  (:require
   [taoensso.timbre :refer [debug info warn error]]
   [buddy.core.codecs :as codecs]
   [buddy.core.hash :as hash]
   [buddy.sign.jwt :as jwt]
   ;[no.nsd.clj-jwt :as clj-jwt]
   [modular.permission.user :refer [get-user]]))

(defn pwd-hash [pwd]
  (-> (hash/blake2b-128 pwd)
      (codecs/bytes->hex)))

(defn create-claim [{:keys [secret] :as this} claim]
  (debug "creating claim: " claim " secret: " secret)
  (let [token (jwt/sign claim secret)]
    (assoc claim :token token)))

(defn get-token [{:keys [users] :as this} user-name user-password]
  ;(info "get-token this keys: " (keys this))
  ; get-token this keys:  (:permission :secret :store :providers)
  (let [user-kw (keyword user-name)
        password-hashed (pwd-hash user-password)
        user (get-user users user-kw)]
    (debug "get-token user: " user-name " user-kw: " user-kw " user-details: "  user)
    (cond
    ; user unknown
      (not user)
      {:error :user-unknown
       :error-message (str "User [" user-name "] not found.")}
     ; password mismatch
      (not (= password-hashed (:password user)))
      {:error :bad-password
       :error-message (str "Bad password for  [" user-name "].")}
     ; succes
      :else
      (create-claim this {:type :local
                          :provider :local
                          :user (:id user)
                          :roles (:roles user)
                          :email (:email user)}))))

(defn verify-token [{:keys [secret] :as this} token]
  ;(info "verifying token: " token " secret: " secret)
  (try
    (cond
      (nil? secret)
      {:error :no-secret
       :error-message "No Secret!"}

      (nil? token)
      {:error :no-token
       :error-message "No Token!"}

      :else
      (let [verify-result (-> (jwt/unsign token secret)
                              (update :user keyword))]
        ;(warn "token verify result:" verify-result)
        verify-result))
    (catch Exception ex
      (error "verify-token exception: " ex)
      {:error :bad-token
       :error-message "Bad Token"})))

(defn login
  [this token]
  (debug "login/local: token: " token)
  (let [{:keys [user error] :as r} (verify-token this token)]
    (if error
      (taoensso.timbre/error "login/local error: " error " token: " token)
      (debug "login/local: result: " r))
    ;(when user (set-user! permission  *session* user))

    r))

(defn login-handler [{:keys [ctx body-params form-params query-params params] :as req}]
  (debug "login-handler body-params: " body-params " form-params: " form-params)
  (let [this (:token ctx)
        params (or body-params form-params {})
        user (or (:user params) (get params "user"))
        password (or (:password params) (get params "password"))]
    (if (and user password)
      (let [{:keys [token error error-message user roles] :as tr} (get-token this user password)]
          ; success:  
          ; {:type :local, :provider :local, :user :florian, :roles #{:logistic}, :email ["hoertlehner@gmail.com"], :token "eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoibG9jYWwiLCJwcm92aWRlciI6ImxvY2FsIiwidXNlciI6ImZsb3JpYW4iLCJyb2xlcyI6WyJsb2dpc3RpYyJdLCJlbWFpbCI6WyJob2VydGxlaG5lckBnbWFpbC5jb20iXX0.JEPHMQMPu44L-OSLBTi4YSmPaIU_Iq0KO_v2hXrIqJM"}
          ; error:
          ; {:error :bad-password, :error-message "Bad password for  [florian]."}
        (debug "token-response: " tr)
        (if error
          {:status 303
           :headers {"location" (str "/login?error=" (java.net.URLEncoder/encode (str error-message) "UTF-8"))}}
          {:status 303
           ;:body token
           :headers {"location" "/me"}
           :cookies {"identity" {:value token
                                 :http-only true
                                 :secure true
                                 :same-site :lax
                                 :path "/"
                                 :max-age (get this :auth-expiry 3600)}}}))
      {:status 303
       :headers {"location" (str "/login?error=" (java.net.URLEncoder/encode "must provide user and password" "UTF-8"))}})))

(defn wrap-identity [handler this]
  (fn [{:keys [cookies] :as req}]
    (cond
      (not cookies)
      (do (error "cannot wrap-identity: no :cookies in ctx)")
          (handler req))

      (not this)
      (do (error "cannot wrap-identity: no :token in ctx)")
          (handler req))

      :else
      (let [;_ (warn "this keys: " (keys this))
            identity-cookie (get cookies "identity")
            token (get identity-cookie :value)]
        (if token
          (let [r (verify-token this token)]
            (debug "verify-token result: " r)
            #_{:type "local", :provider "local",
               :user :florian, :roles ["logistic"],
               :email ["hoertlehner@gmail.com"]}
            (if (:user r)
              (handler (assoc req :identity (select-keys r [:user :roles :email :provider])))
              (do
                (error "no identity")
                (handler req))))
          (do
            (debug "no logged in user")
            ;(warn "no token found in identity cookie.")
            ;(warn "cookies: " cookies)
            ;(warn "identity: " identity-cookie)
            (handler req)))))))

(def identity-middleware
  {:name ::identity
   :compile
   (fn [{:keys [services-ctx] :as route-data} _router-opts]
     (fn [handler]
       (wrap-identity handler (:token services-ctx))))})

(defn wrap-signed-in [handler]
  (fn [{:keys [identity] :as req}]
    (debug "wrap-signed in is checking identity: " identity)
    ;(warn "wrap-signed req keys: " (keys req))
    (if (and identity (:user identity))
      (handler req)
      {:status 303
       :headers {"location" "/login?error=not-signed-in"}})))

(def signed-in-middleware
  {:name ::signed-in
   :compile
   (fn [{:keys [services-ctx] :as route-data} _router-opts]
     (fn [handler] (wrap-signed-in handler)))})

(defn logout-handler [req]
  {:status 303
   :headers {"location" "/me"}
   :cookies {"identity" {:value nil
                         :http-only true
                         :secure true
                         :same-site :lax
                         :path "/"
                         :max-age 0}}})

(defn me-handler [{:keys [identity] :as _req}]
  (if (and identity (some? (:user identity)))
    {:status 200
     :body identity}   
    {:status 200
     :body {:user nil}}))


(comment

  (pwd-hash "1234")
  (pwd-hash "7890")
  (pwd-hash "")

;  (clj-jwt/str->jwt "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGVtbyJ9.mWO7pjUFhFpEDeQT_3OjM1YCZ1TN8LNZiA_3xF-NkBI")

  ; jwks_uri
  ; https://accounts.google.com/.well-known/openid-configuration

 ; (clj-jwt/unsign
 ;  "https://www.googleapis.com/oauth2/v3/certs"
   ;id-token
;   "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQwMWMxYWJlMjQ5MjY5ZjcyZWY3Y2EyNjEzYTg2YzlmMDVlNTk1NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4Nzc3MTk3NDczLWQ4cWp1MWsyZTJvMWhrbGZvdWh0MXYwbTM2aW1nYnJ2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiODc3NzE5NzQ3My1kOHFqdTFrMmUybzFoa2xmb3VodDF2MG0zNmltZ2Jydi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExNzIzMjc5NzY1NjI4MDM5MDg2MSIsImVtYWlsIjoiaG9lcnRsZWhuZXJAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJsOGltUkRtUktfNmdGS0RqNmZWWVlRIiwibm9uY2UiOiIwLjMyMzAxNDQ1MTgzNDgwODgiLCJuYW1lIjoiRmxvcmlhbiBIb2VydGxlaG5lciIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp4RlRUSGNLZDVGNGVZU2JOcUNUXzZzT2pzdm9YZEVuU29ZTDJDVWEzND1zOTYtYyIsImdpdmVuX25hbWUiOiJGbG9yaWFuIiwiZmFtaWx5X25hbWUiOiJIb2VydGxlaG5lciIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjQxNTY0OTk0LCJleHAiOjE2NDE1Njg1OTR9.r_yRMMXXyn75-wSucS3OaLbmBA4viX-Pr9_WVxcbbOFuqDAInXYTLHGr9Z0h1hg_IvY_iTM4HSpHUUNv2x82igz4BI7J8q2ZwI4EwTP16i5K5qMAaQ8op4Pk7YrIpFiuH6Ki7zn3eN-Rx1WlORDiPkyYgCQjDr5XSM94EpygiEk2cTFNP0NK0T7XF80CiliWDqkDTuE3sVPWBLab4x0FVfO5M0dLbL70V0Ede2Unb9WbO566xmZv3hqpER0sVHYc1DcNDRetcIVu9RlCccBE18xqTL8tXnsfGWoCO-POilY-1iPEwCj_SLW8u6Rj0ehYHTK96_hHOnBpxuyL8KPGzg"

   ;"1//05HkiJ3mkxEaeCgYIARAAGAUSNwF-L9IrN6ze8eRTdHMXGkTfRe1tQyjUGHAYWyHwmauFf8ZuWPiWTkS4baZCExUWDqzqwzeqdQg"
   ;"ya29.a0ARrdaM93BFZ3FkKkCEPn3acy9INGwmywONA8_TIFgD5YSfx83Tnn6ojGYbJR3rvEv2rZ2htF5SzaVRXvcv2z9pktxavf5Vp9544qr9UbbVTNFQGjZ-vgshyS43oBU15wzmAfki4TBLD2oJypE8PYOpvyWWJi"
;   )
; xero
; https://identity.xero.com/.well-known/openid-configuration
 ; (clj-jwt/unsign
  ; "https://identity.xero.com/.well-known/openid-configuration/jwks"
   ;"eyJhbGciOiJSUzI1NiIsImtpZCI6IjFDQUY4RTY2NzcyRDZEQzAyOEQ2NzI2RkQwMjYxNTgxNTcwRUZDMTkiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJISy1PWm5jdGJjQW8xbkp2MENZVmdWY09fQmsifQ.eyJuYmYiOjE2NDE1NjcwOTksImV4cCI6MTY0MTU2ODg5OSwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS54ZXJvLmNvbSIsImF1ZCI6Imh0dHBzOi8vaWRlbnRpdHkueGVyby5jb20vcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoiMUQ0RTUxQzMyNDA1NDUxQ0JCQTMyQzExMjkwOUE3QjgiLCJzdWIiOiJkODZhNTIyMThiODk1MDFiODE0ZmIyMDY1YjU5NzNlMSIsImF1dGhfdGltZSI6MTY0MTU2NjQ3OSwieGVyb191c2VyaWQiOiIzYzczNjBjMC02MTk1LTQ2MmQtYjkxMy03NmNlOWM2NmNiYjgiLCJnbG9iYWxfc2Vzc2lvbl9pZCI6IjZjYjZhZjRkNTQ4ZDQ3NDZhZTZjMTNjNWJjOThlOWFmIiwianRpIjoiZTM2Y2NkYzdlMjViOGVlMDFhM2U3YzBkNDAwZDk2OWIiLCJhdXRoZW50aWNhdGlvbl9ldmVudF9pZCI6IjA4ZTg2ZTdiLTZkMjctNDQxMS05MTFiLTY0YjJmMWQ1NzhjMCIsInNjb3BlIjpbImVtYWlsIiwicHJvZmlsZSIsIm9wZW5pZCIsImFjY291bnRpbmcucmVwb3J0cy5yZWFkIiwiYWNjb3VudGluZy5zZXR0aW5ncyIsImFjY291bnRpbmcuYXR0YWNobWVudHMiLCJhY2NvdW50aW5nLnRyYW5zYWN0aW9ucyIsImFjY291bnRpbmcuam91cm5hbHMucmVhZCIsImFjY291bnRpbmcudHJhbnNhY3Rpb25zLnJlYWQiLCJhY2NvdW50aW5nLmNvbnRhY3RzIiwib2ZmbGluZV9hY2Nlc3MiXX0.t9c33xsXXqAfxC8JOyTRPG8b-QrLzqkxIItenXyul3kaSulzue281jed1wFyIpBefDq_xNUfFt4SfrMMyplOxThjQMyYktweyftijfMfnHwa4ZlGJaArdNOFNNzm2XOhdlyjFsVpWrAsMdhb8U9LyZjtagePE90VWyF47N3733tsDj9IBMKOUTg0HVEzyHqR0b-yRXE7KraM9KB3A_-CmuKBjT9JfExfFD8K17vS5T94cHW36EAy1UwWS2NZcFai_nh838Yi4sT1x7HCC3rOJlH8-S-GdmgPXpY5enrJ3nvwhca9bSXQKrnxktubDZeKVV3M1Mfhp5Gr-44Jkzu5Ww")

 ; 
  )


