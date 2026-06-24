defmodule Bonfire.OpenID.Web.OauthConsentLive do
  @moduledoc """
  Scope-consent screen for the OAuth/OpenID `authorize` flow.

  Rendered by the authorize controllers (via `live_render_consent/2`) when a logged-in user has not yet consented to a client + scopes. Mirrors the bonfire_ui_me: a controller `live_render`s this Surface LiveView
  """
  use Bonfire.UI.Common.Web, :surface_live_view_child

  alias Bonfire.OpenID.Web.Consent

  on_mount {LivePlugs,
            [
              Bonfire.UI.Me.LivePlugs.UserRequired
            ]}

  @doc "Called by the authorize controllers to render the consent screen for a validated request."
  def live_render_consent(conn, authorization) do
    # key consent on the scope as requested in the query, so `remember_consent` (on Allow)
    # and `consented?` (on the re-invoked authorize) use the same value
    scope = conn.query_params["scope"] || e(authorization, :requested_scope, nil)
    client = e(authorization, :client, nil)

    data = %{
      client_id: e(client, :id, conn.query_params["client_id"]),
      client_name: e(client, :name, nil),
      client_logo: e(client, :logo_uri, nil),
      requested_scope: scope,
      scopes: Consent.scopes_for_display(scope, client),
      redirect_uri: e(authorization, :redirect_uri, nil) || conn.query_params["redirect_uri"],
      state: e(authorization, :state, nil) || conn.query_params["state"],
      login_hint: conn.query_params["login_hint"],
      go: Phoenix.Controller.current_path(conn, conn.query_params)
    }

    live_render_with_data(conn, data)
  end

  defp live_render_with_data(conn, data) do
    Phoenix.LiveView.Controller.live_render(conn, __MODULE__, session: %{"oauth_consent" => data})
  end

  def mount(_params, session, socket) do
    data = session["oauth_consent"] || %{}
    login_hint = Map.get(data, :login_hint)

    {:ok,
     assign(socket,
       oauth_consent: data,
       client_name: Map.get(data, :client_name),
       client_logo: Map.get(data, :client_logo),
       scopes: Map.get(data, :scopes, []),
       # offer switching profiles unless the client asked for a specific one
       allow_switch_profile?: is_nil(login_hint) or login_hint == "",
       go: Bonfire.UI.Common.copy_go(%{"go" => Map.get(data, :go)}),
       without_sidebar: true,
       no_header: true,
       without_secondary_widgets: true,
       page_title: l("Authorize access")
     )}
  end

  def handle_event("allow", _params, socket) do
    data = e(assigns(socket), :oauth_consent, %{})

    Consent.remember_consent(
      current_user(socket),
      Map.get(data, :client_id),
      Map.get(data, :requested_scope)
    )

    # re-invoke the OAuth authorize flow, which will now find consent and issue the code
    {:noreply, redirect_to(socket, Map.get(data, :go))}
  end

  def handle_event("deny", _params, socket) do
    data = e(assigns(socket), :oauth_consent, %{})

    query =
      %{"error" => "access_denied"}
      |> maybe_put("state", Map.get(data, :state))

    deny_url = "#{Map.get(data, :redirect_uri)}?#{URI.encode_query(query)}"

    {:noreply, redirect_to(socket, deny_url, type: :maybe_external)}
  end
end
