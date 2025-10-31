// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Item struct {
	ID    string `bson:"_id,omitempty" json:"id,omitempty"`
	Name  string `bson:"name" json:"name"`
	Value int    `bson:"value" json:"value"`
}

func main() {
	// Connect to MongoDB
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://mongo:27017"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("testdb")
	coll := db.Collection("items")

	http.HandleFunc("/mongo", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Second)
		defer cancel()

		// Insert one
		item := Item{Name: "foo", Value: 42}
		insertResult, err := coll.InsertOne(ctx, item)
		if err != nil {
			http.Error(w, "Insert error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Find one
		var found Item
		err = coll.FindOne(ctx, bson.M{"_id": insertResult.InsertedID}).Decode(&found)
		if err != nil {
			http.Error(w, "Find error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update one
		_, err = coll.UpdateOne(ctx, bson.M{"_id": insertResult.InsertedID}, bson.M{"$set": bson.M{"value": 100}})
		if err != nil {
			http.Error(w, "Update error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Find updated
		var updated Item
		err = coll.FindOne(ctx, bson.M{"_id": insertResult.InsertedID}).Decode(&updated)
		if err != nil {
			http.Error(w, "Find after update error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete one
		_, err = coll.DeleteOne(ctx, bson.M{"_id": insertResult.InsertedID})
		if err != nil {
			http.Error(w, "Delete error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Respond with the results
		result := map[string]interface{}{
			"inserted": item,
			"found":    found,
			"updated":  updated,
			"deleted":  true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
