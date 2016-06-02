(ns auth0-cljs.ajax
  (:require [auth0-cljs.user :refer [get-user-token]]
            [cljs-http.client :as http]))

(defn request
  [request-fn endpoint args]
  (if-let [token (get-user-token)]
    (let [header (str "Bearer " token)]
      (request-fn endpoint (merge-with merge {:headers {"Authorization" header}} args)))

    ;; TODO: returning nil is bad here
    nil))

(defn get
  ([endpoint] (get endpoint {}))
  ([endpoint args]
   (request http/get endpoint args)))

(defn post
  ([endpoint] (post endpoint {}))
  ([endpoint args]
   (request http/post endpoint args)))

(defn put
  ([endpoint] (put endpoint {}))
  ([endpoint args]
   (request http/put endpoint args)))

(defn delete
  ([endpoint] (delete endpoint {}))
  ([endpoint args]
   (request http/delete endpoint args)))


