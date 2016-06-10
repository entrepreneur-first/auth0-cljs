(ns auth0-cljs.user
  (:require [cemerick.url :refer [url url-encode]]))

(def logged-in-user (atom {}))

(defn get-user-token
  "Gets the Auth0 user token from local storage"
  []
  (.getItem js/localStorage "userToken"))

(defn set-user-token!
  "Sets the Auth0 user token in local storage"
  [token]
  (.setItem js/localStorage "userToken" token))

(defn clear-user-token!
  "Clears the Auth0 user token (e.g. for logout)"
  []
  (.removeItem js/localStorage "userToken"))

(defn global-logout!
  "Clears OUR token, and does an SSO logout"
  [auth0-subdomain auth0-client-id]
  (clear-user-token!)
  (let [location (.-location js/window)]

    (set! (.-href location)
          (str (url (str "https://" auth0-subdomain ".auth0.com") "/v2/logout" :query {:returnTo (.-href location) :client_id auth0-client-id}
                    )))))