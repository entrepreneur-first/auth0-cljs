(ns auth0-cljs.ajax
  (:require-macros [cljs.core.async.macros :refer [go]])
  (:require
            [cljs-http.client :as http]
            [cljs.core.async :refer [<! >! chan]]
            [auth0-cljs.user :as user]))

(defn request
  "WARNING - logs you out if the auth0-cljs user token is not set"
  [request-fn endpoint args]
  (let [response-channel (chan)]
    (if-let [token (user/get-user-token)]
      (go
       (let [header (str "Bearer " token)
             resp (<! (request-fn endpoint (merge-with merge {:headers {"Authorization" header}} args)))]
         (if (= 401 (:status resp))
           (do
             (user/clear-user-token!)
             (set! (.-href (.-location js/window)) ""))
           (>! response-channel resp))))

      (do
        (user/clear-user-token!)
        (set! (.-href (.-location js/window)) "")))

    response-channel))

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


