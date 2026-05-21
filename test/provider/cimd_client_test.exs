defmodule Bonfire.OpenID.Client.CIMDClientTest do
  use Bonfire.OpenID.ConnCase

  alias Bonfire.OpenID.Client

  setup do
    {:ok, conn: build_conn()}
  end

  describe "cimd_client_id/0" do
    test "returns a URL ending in /.well-known/oauth-client" do
      id = Client.cimd_client_id()
      assert String.ends_with?(id, "/.well-known/oauth-client")
    end
  end

  describe "cimd_document/0" do
    test "client_id matches the well-known URL" do
      doc = Client.cimd_document()
      assert doc["client_id"] == Client.cimd_client_id()
    end

    test "client_name includes the hostname" do
      doc = Client.cimd_document()
      host = URI.parse(Client.cimd_client_id()).host
      assert doc["client_name"] =~ host
    end

    test "redirect_uris is a list" do
      doc = Client.cimd_document()
      assert is_list(doc["redirect_uris"])
    end

    test "required CIMD fields are present" do
      doc = Client.cimd_document()
      assert is_binary(doc["client_id"])
      assert is_binary(doc["client_name"])
      assert is_binary(doc["client_uri"])
      assert is_list(doc["redirect_uris"])
      assert is_list(doc["grant_types"])
      assert "authorization_code" in doc["grant_types"]
      assert doc["token_endpoint_auth_method"] == "none"
    end
  end

  describe "GET /.well-known/oauth-client" do
    test "returns 200 with valid CIMD JSON", %{conn: conn} do
      conn = get(conn, "/.well-known/oauth-client")
      body = json_response(conn, 200)
      assert body["client_id"] == Client.cimd_client_id()
      assert is_list(body["redirect_uris"])
      assert body["token_endpoint_auth_method"] == "none"
    end

    test "content-type is application/json", %{conn: conn} do
      conn = get(conn, "/.well-known/oauth-client")
      assert get_resp_header(conn, "content-type") |> hd() =~ "application/json"
    end
  end

  describe "GET /.well-known/oauth-authorization-server" do
    test "declares client_id_metadata_document_supported and own client_id", %{conn: conn} do
      conn = get(conn, "/.well-known/oauth-authorization-server")
      body = json_response(conn, 200)
      assert body["client_id_metadata_document_supported"] == true
      assert body["client_id"] == Client.cimd_client_id()
    end
  end
end
