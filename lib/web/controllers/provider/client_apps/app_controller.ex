defmodule Bonfire.API.MastoCompatible.AppController do
  use Bonfire.UI.Common.Web, :controller
  alias Bonfire.Common.Config
  alias Bonfire.OpenID.Web.OauthView
  alias Bonfire.OpenID.Provider.ClientApps

  def create(conn, params) do
    # curl -X POST \
    # -F 'client_name=Test Application' \
    # -F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob' \
    # -F 'scopes=read write push' \
    # -F 'website=https://myapp.example' \
    # https://instance.example/api/v1/apps

    # TODO: don't re-create if one already exists
    with {:ok, client} <-
           ClientApps.new(%{
             name: String.trim("#{params["client_name"]} #{params["website"]}"),
             redirect_uris: ClientApps.prepare_redirect_uris(params["redirect_uris"])
             # _: params["scopes"], # TODO
           }) do
      json(conn, %{
        "id" => client.id,
        "name" => client.name,
        "website" => nil,
        "redirect_uri" => List.first(client.redirect_uris || []),
        "client_id" => client.id,
        "client_secret" => client.secret
        # "vapid_key"=> client.vapid_key # TODO?
      })
    else
      other ->
        error(other)

        conn
        |> put_status(500)
        |> put_view(OauthView)
        |> render("error.json",
          error: "Could not create a client",
          error_description: inspect(other)
        )
    end
  end
end
