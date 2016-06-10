(ns auth0-cljs.user)

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