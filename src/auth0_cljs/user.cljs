(ns auth0-cljs.user
  (:import goog.net.Cookies))

(def logged-in-user (atom {}))

(defn get-user-token
  "Gets the Auth0 user token from local storage"
  []
  (.get (goog.net.Cookies. js/document) "auth0-cljs-user-token"))

(defn set-user-token!
  "Sets the Auth0 user token in local storage"
  [token]
  (.set (goog.net.Cookies. js/document) "auth0-cljs-user-token" token -1 "/"))

(defn clear-user-token!
  "Clears the Auth0 user token (e.g. for logout)"
  []
  (.set (goog.net.Cookies. js/document) "auth0-cljs-user-token" "" 0 "/"))