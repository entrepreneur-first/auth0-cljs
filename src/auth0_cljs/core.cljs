(ns auth0-cljs.core
  (:require-macros [cljs.core.async.macros :refer [go]])
  (:require [auth0-cljs.ajax]
            [auth0-cljs.user :as user]
            [cemerick.url :refer [url]]
            [cljs.core.async :refer [<! timeout]]
            [cljs-http.client :as http]
            [cljsjs.auth0-lock]))

(defn global-logout!
  "Clears OUR token, and does an SSO logout"
  [auth0-subdomain auth0-client-id]
  (user/clear-user-token!)
  (let [location (.-location js/window)]
    (set! (.-href location)
      (str (-> (url (str "https://" auth0-subdomain ".auth0.com") "/v2/logout")
               (assoc :query {:returnTo (.-href location) :client_id auth0-client-id}))))))

(defn attempt-signin!
  "Attempts to sign-in automagically, presumably using SSO creds."
  [lock]
  (let [auth0 (.getClient lock)]
    (.signin
      auth0
      (clj->js
        {:callbackOnLocationHash true
         :scope "openid name picture"
         :sso true
         :state (pr-str {:href (.-hash (.-location js/window))})}))))

(defn getSSOData
  "Replacement for the idiotic auth0 version"
  [auth0-subdomain callback]
  (go
    (let [resp (<! (http/get (str (url (str "https://" auth0-subdomain ".auth0.com") "/user/ssodata"))
                     {:timeout 5000}))]
      (if (= (:status resp) 200)
        (callback nil (:body resp))
        (callback resp nil)))))

(defn check-sso-status!
  "Where the magic happens.

  Checks to see if Auth0 thinks we have an SSO login active for this app.

  on-active-callback - function of one argument if SSO login is active on-inactive-callback - function of one argument
   is SSO is inactive on-error-callback - function of one argument to be called on error."
  [auth0-subdomain
   ;on-available-callback
   on-inactive-callback on-error-callback]
  (getSSOData
    auth0-subdomain
    (fn [error data]
      (cond
        error (on-error-callback error)
        ;(and data (:sso data)) (on-available-callback data)
        :else (on-inactive-callback data)))))

(defn setup-polling-for-sso-logout!
  "It's possible that someone has logged out in another session.
  Let's poll every <interval> seconds and check.

  TODO: Check that the *same* account is logged in."
  [auth0-subdomain interval]
  (js/setInterval
    (fn []
      ; TODO: work out why SSO isn't working for impersonated users
      (when (and (user/get-user-token) (not (:impersonated @user/logged-in-user)))
        (check-sso-status!
          auth0-subdomain
          ;(fn [_data])

          (fn [_data]
            #_(when-not (:impersonated @user/logged-in-user)
                (.log js/console "SSO LOGOUT")
                (reset! user/logged-in-user nil)
                (user/clear-user-token!)
                (set! (.-href (.-location js/window)) "")))

          (fn [_error]
            (js/console.log "SSO ERROR")
            (js/console.log (clj->js _error))))))
    interval))

(defn get-redirect-url
  [href]
  (first (clojure.string/split href #"\#")))

(defn safe-read-edn
  [s]
  (try
    (cljs.reader/read-string s)
    (catch :default e)))

(defn ensure-logged-in!
  "Checks for authenticated user, and if not then pops up the Auth0 login modal.

   In the case of a previous failed login (authorization_error or unrecoverable_error), we capture the error message
   returned from the Auth0 server and log it to the javascript console. We clear the error message from the URL hash to
   prevent us getting stuck in an infinite loop."
  ([auth0-client-id auth0-subdomain user-info-endpoint callback-fn]
   (ensure-logged-in! auth0-client-id auth0-subdomain user-info-endpoint callback-fn {}))
  ([auth0-client-id auth0-subdomain user-info-endpoint callback-fn login-modal-overrides]
   (let [location (.-location js/window)
         state (pr-str {:href (.-hash location)})
         lock (doto
                (js/Auth0Lock. auth0-client-id (str auth0-subdomain ".auth0.com")
                  (clj->js
                    (merge
                      {:popup true
                       :auth {:responseType "token"
                              :audience "https://entrepreneurfirst.eu.auth0.com/userinfo"
                              :params {:state state}
                              :scope "openid name picture profile"
                              :autoParseHash true
                              :sso true
                              :callbackURL (get-redirect-url (.-href location))
                              :closable false}}
                      login-modal-overrides)))
                (.on "authenticated"
                  (fn [auth-result]
                    (let [access-token (.-accessToken auth-result)
                          state (.-state auth-result)]
                      (user/set-user-token! access-token)
                      (set! (.-href location) (get (safe-read-edn state) :href ""))
                      (.reload location))))
                (.on "authorization_error"
                  (fn [error]
                    (js/console.error (str "authorization_error: " error))
                    (.replaceState js/history {} (.-title js/document) (.-pathname location))))
                (.on "unrecoverable_error"
                  (fn [error]
                    (js/console.error (str "unrecoverable_error: " error))
                    (.replaceState js/history {} (.-title js/document) (.-pathname location)))))]
     (if (user/get-user-token)
       (do
         (setup-polling-for-sso-logout! auth0-subdomain 5000)
         (go
           (let [{:keys [status body]} (<! (auth0-cljs.ajax/get user-info-endpoint))]
             (case status
               200 (do (reset! user/logged-in-user body)
                       (callback-fn body))
               (js/console.error (str "Unexpected http request status: " status))))))
       (check-sso-status!
         auth0-subdomain
         ;(fn [_data] (attempt-signin! lock)) ;; TODO consider making SSO work https://auth0.com/docs/libraries/lock/v10/migration-guide#removed-methods
         (fn [_data] (.show lock))
         (fn [_err]))))))