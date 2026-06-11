if Application.compile_env(:bonfire_api_graphql, :modularity) != :disabled do
  defmodule Bonfire.OpenID.Web.MastoTokensController do
    @moduledoc "OAuth token management (`/api/v1/tokens`)."

    use Bonfire.UI.Common.Web, :controller

    alias Bonfire.OpenID.API.MastoTokens.Adapter

    def index(conn, params), do: Adapter.index(params, conn)
    def show(conn, params), do: Adapter.show(params, conn)
    def invalidate(conn, params), do: Adapter.invalidate(params, conn)
  end
end
