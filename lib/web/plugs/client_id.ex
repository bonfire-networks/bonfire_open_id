defmodule Bonfire.OpenID.Plugs.ClientID do
  use Bonfire.UI.Common.Web, :plug

  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.OpenID.Provider.CIMD

  # pattern from `Boruta.Oauth.Json.Schema`
  # @uuid_pattern "\^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\$"

  def validate_client_id(
        %{params: %{"client_id" => client_id, "redirect_uri" => redirect_uri}} = conn,
        _opts
      )
      when is_binary(client_id) and byte_size(client_id) == 36 do
    if Regex.match?(
         ~r/^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}/,
         client_id
       ),
       do: conn,
       else: resolve_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(
        %{params: %{"client_id" => client_id, "redirect_uri" => redirect_uri}} = conn,
        _opts
      ) do
    resolve_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(conn, _opts) do
    conn
  end

  defp resolve_client(conn, client_id, redirect_uri)
       when is_binary(client_id) and is_binary(redirect_uri) do
    if CIMD.cimd_client_id?(client_id) do
      register_cimd_client(conn, client_id, redirect_uri)
    else
      # Clients are only created through registration (`/api/v1/apps`, `/openid/register`), never by an unauthenticated authorize request
      case ClientApps.get_by_id(ClientApps.id_or_name_to_id(String.trim(client_id))) do
        %{id: id} -> put_client_id(conn, id)
        nil -> reject(conn, 400, "Unknown client_id")
      end
    end
  end

  defp resolve_client(conn, _client_id, _redirect_uri), do: conn

  # If client_id is a URL, fetch and validate its metadata via CIMD before registering
  defp register_cimd_client(conn, client_id, redirect_uri) do
    # Detect PKCE (code_challenge/code_challenge_method) in params
    pkce_attrs =
      if conn.params["code_challenge"] || conn.params["code_challenge_method"] do
        %{confidential: false, pkce: true}
      else
        %{}
      end

    case CIMD.fetch(client_id) do
      {:ok, %{redirect_uris: uris, name: name, grant_types: grants, scope: scope}} ->
        prepared_uris = Enum.map(uris, &ClientApps.prepare_redirect_uri/1)

        attrs =
          Map.merge(pkce_attrs, %{
            name: name,
            redirect_uris: prepared_uris,
            # never `password` or `implicit`: the metadata document is not trusted
            supported_grant_types: List.wrap(grants) -- ["password", "implicit"],
            authorized_scopes:
              ClientApps.scopes_maps(
                ClientApps.registrable_scopes(scope, ClientApps.non_admin_scopes())
              )
          })

        # Use the request redirect_uri if it's listed in the CIMD doc, else fall back to first listed
        prepared_redirect_uri = ClientApps.prepare_redirect_uri(redirect_uri)

        registration_redirect_uri =
          if prepared_redirect_uri in prepared_uris,
            do: prepared_redirect_uri,
            else: List.first(prepared_uris, prepared_redirect_uri)

        case ClientApps.get_or_new(String.trim(client_id), registration_redirect_uri, attrs) do
          {:ok, %{id: id} = client} ->
            # A CIMD client is resolved by a deterministic id derived from its
            # client_id URL, so an already-registered client is returned as-is and
            # its stored redirect_uris can be stale if the hosted CIMD document has
            # changed since first registration. Reconcile them with the freshly
            # fetched document so edits to client.jsonld propagate automatically
            # (Boruta loads the client by id later in the pipeline, after this plug).
            maybe_sync_cimd_redirect_uris(client, prepared_uris)

            put_client_id(conn, id)

          {:error, changeset} ->
            conn
            |> assign(:client_id_error, changeset)
            |> reject(500, "Error when registering with your client_id or redirect_uri")
        end

      {:error, reason} ->
        reject(conn, 400, "Invalid client_id: #{reason}")
    end
  end

  defp put_client_id(conn, id) do
    %{
      conn
      | query_params: Map.put(conn.query_params, "client_id", id),
        params: Map.put(conn.params, "client_id", id),
        body_params: Map.put(conn.body_params, "client_id", id)
    }
  end

  defp reject(conn, status, message) do
    conn
    |> Plug.Conn.send_resp(status, message)
    |> Plug.Conn.halt()
  end

  # Keep an existing CIMD client's redirect_uris in sync with its metadata
  # document. No-op for freshly-created clients (already built from the doc). Only writes when the set differs.
  defp maybe_sync_cimd_redirect_uris(client, doc_redirect_uris)
       when is_list(doc_redirect_uris) and doc_redirect_uris != [] do
    if MapSet.new(client.redirect_uris || []) == MapSet.new(doc_redirect_uris) do
      {:ok, client}
    else
      ClientApps.update_redirect_uris(client, doc_redirect_uris)
    end
  end

  defp maybe_sync_cimd_redirect_uris(client, _doc_redirect_uris), do: {:ok, client}
end
