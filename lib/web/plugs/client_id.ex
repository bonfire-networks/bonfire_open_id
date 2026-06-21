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
       else: maybe_register_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(
        %{params: %{"client_id" => client_id, "redirect_uri" => redirect_uri}} = conn,
        _opts
      ) do
    maybe_register_client(conn, client_id, redirect_uri)
  end

  def validate_client_id(conn, _opts) do
    conn
  end

  defp maybe_register_client(conn, client_id, redirect_uri)
       when is_binary(client_id) and is_binary(redirect_uri) do
    # Detect PKCE (code_challenge/code_challenge_method) in params
    pkce_attrs =
      if conn.params["code_challenge"] || conn.params["code_challenge_method"] do
        %{confidential: false, pkce: true}
      else
        %{}
      end

    # If client_id is a URL, fetch and validate metadata via CIMD before registering
    {cimd_attrs, doc_redirect_uris} =
      if CIMD.cimd_client_id?(client_id) do
        case CIMD.fetch(client_id) do
          {:ok, %{redirect_uris: uris, name: name, grant_types: grants, scope: scope}} ->
            prepared_uris = Enum.map(uris, &ClientApps.prepare_redirect_uri/1)

            attrs = %{
              name: name,
              redirect_uris: prepared_uris,
              supported_grant_types: grants,
              supported_scopes: scope
            }

            {attrs, prepared_uris}

          {:error, reason} ->
            conn
            |> Plug.Conn.send_resp(400, "Invalid client_id: #{reason}")
            |> Plug.Conn.halt()

            {%{}, []}
        end
      else
        {%{}, []}
      end

    attrs = Map.merge(pkce_attrs, cimd_attrs)

    # Use the request redirect_uri if it's listed in the CIMD doc, else fall back to first listed
    prepared_redirect_uri = ClientApps.prepare_redirect_uri(redirect_uri)

    registration_redirect_uri =
      if doc_redirect_uris == [] or prepared_redirect_uri in doc_redirect_uris,
        do: prepared_redirect_uri,
        else: List.first(doc_redirect_uris, prepared_redirect_uri)

    case ClientApps.get_or_new(
           String.trim(client_id),
           registration_redirect_uri,
           attrs
         ) do
      {:ok, %{id: id} = client} ->
        # A CIMD client is resolved by a deterministic id derived from its
        # client_id URL, so an already-registered client is returned as-is and
        # its stored redirect_uris can be stale if the hosted CIMD document has
        # changed since first registration. Reconcile them with the freshly
        # fetched document so edits to client.jsonld propagate automatically
        # (Boruta loads the client by id later in the pipeline, after this plug).
        maybe_sync_cimd_redirect_uris(client, doc_redirect_uris)

        %{
          conn
          | query_params:
              conn.query_params
              |> Map.put("client_id", id),
            params:
              conn.params
              |> Map.put("client_id", id),
            body_params:
              conn.body_params
              |> Map.put("client_id", id)
        }

      {:error, changeset} ->
        # Assign error and halt the conn, or handle as needed
        conn
        |> assign(:client_id_error, changeset)
        |> Plug.Conn.send_resp(500, "Error when registering with your client_id or redirect_uri")
        |> Plug.Conn.halt()
    end
  end

  defp maybe_register_client(conn, _client_id, _redirect_uri), do: conn

  # Keep an existing CIMD client's redirect_uris in sync with its metadata
  # document. No-op for freshly-created clients (already built from the doc) and
  # for non-CIMD clients (empty doc list). Only writes when the set differs.
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
