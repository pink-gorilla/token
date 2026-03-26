(ns token.oauth2.provider.default
  (:require
   [taoensso.timbre :as timbre :refer [debug info warn error]]
   [token.oauth2.provider.google :as google] ; side-effects
   [token.oauth2.provider.github :as github] ; side-effects
   [token.oauth2.provider.xero :as xero] ; side-effects
      ;[token.oauth2.provider.woo :as woo] ; side-effects
   ))

(info "default oauth2-providers (google/github/xero) loaded.")