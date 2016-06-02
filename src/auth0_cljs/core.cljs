(ns auth0-cljs.core
  (:require-macros [cljs.core.async.macros :refer [go]])
  (:require [cljsjs.auth0-lock]
            [cljs-http.client :as http]
            [cljs.core.async :refer [<! timeout]]
            [auth0-cljs.user :as user]
            [auth0-cljs.ajax]))

(defn global-logout!
  "Clears OUR token, and does an SSO logout"
  [auth0-subdomain auth0-client-id]
  (user/clear-user-token!)
  (let [location (.-location js/window)]

    ; TODO: Don't use str for URL joining.. this is silly
    (set! (.-href location)
          (str "https://" auth0-subdomain ".auth0.com/v2/logout?returnTo="
               (.-href location)
               "&client_id="
               auth0-client-id))))

(defn show-login-modal!
  "Pops up the Auth0 login modal.

  TODO: this should probably take some overrides."
  [lock callback-url]
  (.show
   lock
   (clj->js {:authParams       {:scope       "openid name picture"
                                :access_type "offline"
                                :state       (.-hash (.-location js/window))}
             :callbackURL      callback-url
             :responseType     "token"
             :dict             {
                                :signin {
                                         :title "Log-in to EF"
                                         }
                                }
             ; TODO: change this to a static file that we actually control
             :icon             "https://s3-eu-west-1.amazonaws.com/e-core-production/uploads/company/517337fd17b87964ae0012d3/logo/EF_Solo_Black.png"
             :socialBigButtons true
             :closable         false
             :primaryColor     "#051932"})))

(defn attempt-signin!
  "Attempts to sign-in automagically,
  presumably using SSO creds."
  [lock]
  (let [auth0 (.getClient lock)]
    (.signin
     auth0
     (clj->js
      {:callbackOnLocationHash true
       :scope                  "openid name picture"
       :sso                    true
       :state                  (.-hash (.-location js/window))}))))

(defn getSSOData
  "Replacement for the idiotic auth0 version"
  [auth0-subdomain callback]
  (go
   (let [resp (<! (http/get (str "https://" auth0-subdomain ".auth0.com" "/user/ssodata")
                            {:timeout 5000}))]
     (if (= (:status resp) 200)
       (callback nil (:body resp))
       (callback resp nil)))))

(defn check-sso-status!
  "Where the magic happens.

  Checks to see if Auth0 thinks we have an SSO
  login active for this app.

  on-active-callback - function of one argument if SSO login is active
  on-inactive-callback - function of one argument is SSO is inactive
  on-error-callback - function of one argument to be called on error."
  [auth0-subdomain on-available-callback on-inactive-callback on-error-callback]
  (getSSOData
   auth0-subdomain
   (fn [error data]
     (cond
       error (on-error-callback error)

       (and data (:sso data)) (on-available-callback data)

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
        (fn [_data])

        (fn [_data]
          (when-not (:impersonated @user/logged-in-user)
            (.log js/console "SSO LOGOUT")
            (reset! user/logged-in-user nil)
            (user/clear-user-token!)
            (set! (.-href (.-location js/window)) "")))

        (fn [_error]
          (.log js/console "SSO ERROR")
          (.log js/console (clj->js _error))))))
   interval))


(defn get-redirect-url
  [href]
  (first (clojure.string/split href #"\#")))

(defn ensure-logged-in!
  [auth0-client-id auth0-subdomain user-info-endpoint callback-fn]
    (let [lock (js/Auth0Lock. auth0-client-id (str auth0-subdomain ".auth0.com"))
        hash (.parseHash lock (.-hash (.-location js/window)))]

    (when hash
      (when-let [id-token (aget hash "id_token")]
        (user/set-user-token! id-token)
        (.log js/console (str "State is: " (.-state hash)))
        (set! (.-href (.-location js/window)) (or (.-state hash) ""))))

    (if (user/get-user-token)

      (do
        (setup-polling-for-sso-logout! auth0-subdomain 5000)
        (go
          (let [resp (<!
                       (auth0.ajax/get user-info-endpoint))
                user-info (:body resp)]
            (reset! user/logged-in-user user-info)
            (callback-fn user-info))))

      (do
        (check-sso-status!
         auth0-subdomain
         (fn [_data] (attempt-signin! lock))
         (fn [_data] (show-login-modal! lock (get-redirect-url (.-href (.-location js/window)))))
         (fn [_err]))))))