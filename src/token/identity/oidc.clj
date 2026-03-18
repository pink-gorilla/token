(ns token.identity.oidc
  (:require
   [taoensso.timbre :refer [debug info warn] :as timbre]
   [modular.permission.user :refer [find-user-id-via-email get-user]]
   [token.oauth2.provider :as provider]
   [token.identity.oidc.util :as util]
   [token.identity.local :refer [create-claim]]))

;; OIDC login

(defn validate-token [jwt jwks alg]
  (try
    ;(warn "validate token: " jwt " jwks: " jwks " alg: " alg)
    (util/validate-jwt jwt jwks alg)
    (catch Exception ex
      (timbre/error "oidc token validate exception: " ex)
      false)))

(defn login
  [{:keys [users] :as this} {:keys [provider id-token]}]
  (debug "login/oauth2-oidc: id-token: " id-token " provider " provider)
  ;(warn "oauth2->login ctx keys:" (keys this))
  (let [;email (user-email token)
        jwks-url  (provider/oauth2-jwks-uri {:provider provider})
        ;_ (info "getting jwks for provider: " provider " url: " jwks-url)
        jwks (util/get-jwks jwks-url)
        #_{:keys [{:alg "RS256", :use "sig", :kty "RSA", :e "AQAB",
                   :kid "d275407c39e8036aa735eb2c17c548761ced6a64",
                   :n "vMB8sa7i5JUTgnd8FNsoVL6-5-0DVGYmUdkdSnMetRpJb7rUi1JyLYCGO0IYG3uzZ-5Bj13z72hWeHc-NfFT27N8OuHriAjp5jdEtUUOYIiZCQl_C1Asg_eTJB-DaRGIZjIXlx_nwYXc4fmDaLUaIFdSLkCHCbdYrKuF4GcPMCbIdJehhSyeUEeH4yjy14YagMxR-k2DNRoWYhpKtyw4VXOA5uLdZoev5q-5B3HRMLknF73GyussSvh4yV9MZCcSNL6rWHKZ9sl_Ap2w15tWkrUhTc-iD8H9ygqAq46_H9ypLouw2OuLTg6hDe5sjfnsTPlmBzAZJF4UI-p2LqUBFw"}
                  {:use "sig", :e "AQAB", :kty "RSA", :alg "RS256",
                   :kid "2507f51af2a16246707484674a42ae3c2b62319c"
                   :n "qSvfLp-BxbSTzbQpDLxEuszN0MnB0qx0lXLuFPX4xmcnfU2n7e1cfLAIKqhMxV8upP6jJYhA5RGHaDQOG3g8V56vWSZx96xJwwtUYeZ_dpemagveZshIC0vHpRfl8DPeeT5zD-cE-OvY2V1JeLnMvXxAoe0eqtDOwBTz62BcP4Jfqaw_-MS8lLrGP_ZvJPKiy1oW5fklPtGT9VwieaOccY7PBYxUeUwVmTHRg85eBp3br45pinPxEeimo6qHcd3wLAOkkwkh0BuJM5csDlfug69ohzf8-qEqNqpIPwWg1RDCsCLn86t5z-dCzqCX487BTD8f7xI9eS5uBVQeDF6BmQ"}]}

        alg {:alg :rs256}
        ;jwt (util/token->id-jwt token)
        ;_ (info "jwt token (access token): " jwt)
        {:keys [error email] :as validation-response} (validate-token id-token jwks alg)
        user-id (when email (find-user-id-via-email users email))]
    (debug "login/oauth2-oidc:validation-response: " validation-response)
    (cond

      (not email)
      {:status 404 :body "no email found in token"}

      (not user-id)
      {:status 404 :body (str "no user found for email: " email)}

      :else
      (let [user (get-user users user-id)
            claim (create-claim this {:type :oidc
                                      :provider provider
                                      :user (:id user)
                                      :roles (:roles user)
                                      :email (:email user)})]
        (debug "perfect! logging in user: " user)
        (debug "claim: " claim)
        {:status 303
         :headers {"location" "/me"}
         :cookies {"identity" {:value (:token claim)
                               :http-only true
                               :secure true
                               :same-site :lax
                               :path "/"
                               :max-age (get this :auth-expiry 3600)}}}))))