if Application.compile_env(:bonfire_api_graphql, :modularity) != :disabled do
  defmodule Bonfire.OpenID.API.MastoTokens.Adapter do
    @moduledoc """
    OAuth token management endpoints:
    - GET  /api/v1/tokens               - list the current user's tokens
    - GET  /api/v1/tokens/:id           - get one token
    - POST /api/v1/tokens/:id/invalidate - revoke one token

    Tokens are OAuth infrastructure (Boruta), so this reads/writes the token store
    directly via `Bonfire.OpenID.Provider.Tokens` rather than through GraphQL.
    """

    use Bonfire.Common.Utils

    alias Bonfire.API.GraphQL.RestAdapter
    alias Bonfire.API.MastoCompat.{Mappers, PaginationHelpers}
    alias Bonfire.OpenID.Provider.Tokens

    @doc "List the current user's active access tokens (paginated, newest first)."
    def index(params, conn) do
      RestAdapter.with_current_user(conn, fn user ->
        limit = PaginationHelpers.validate_limit(params["limit"], default: 20, max: 40)

        tokens =
          Tokens.list_for_user(id(user),
            limit: limit,
            max_id: params["max_id"],
            min_id: params["min_id"],
            since_id: params["since_id"]
          )

        conn
        |> maybe_link_headers(tokens, limit)
        |> RestAdapter.json(Enum.map(tokens, &Mappers.Token.from_oauth_token/1))
      end)
    end

    @doc "Get a single token owned by the current user."
    def show(%{"id" => token_id}, conn) do
      RestAdapter.with_current_user(conn, fn user ->
        case Tokens.get_for_user(id(user), token_id) do
          {:ok, token} -> RestAdapter.json(conn, Mappers.Token.from_oauth_token(token))
          {:error, _} -> RestAdapter.error_fn({:error, :not_found}, conn)
        end
      end)
    end

    @doc "Invalidate (revoke) a token owned by the current user."
    def invalidate(%{"id" => token_id}, conn) do
      RestAdapter.with_current_user(conn, fn user ->
        case Tokens.invalidate_for_user(id(user), token_id) do
          {:ok, token} -> RestAdapter.json(conn, Mappers.Token.from_oauth_token(token))
          {:error, _} -> RestAdapter.error_fn({:error, :not_found}, conn)
        end
      end)
    end

    defp maybe_link_headers(conn, [], _limit), do: conn

    defp maybe_link_headers(conn, tokens, limit) do
      base = Bonfire.Common.URIs.base_url() <> "/api/v1/tokens"
      first_id = List.first(tokens).id
      last_id = List.last(tokens).id

      # "next" (older) only when the page was full; "prev" (newer) whenever we have results
      next =
        if length(tokens) >= limit, do: ["<#{base}?max_id=#{last_id}>; rel=\"next\""], else: []

      prev = ["<#{base}?min_id=#{first_id}>; rel=\"prev\""]

      conn
      |> Plug.Conn.put_resp_header("link", Enum.join(next ++ prev, ", "))
      |> Plug.Conn.put_resp_header("access-control-expose-headers", "Link")
    end
  end
end
