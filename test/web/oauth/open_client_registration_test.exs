defmodule Bonfire.OpenID.Web.OpenClientRegistrationTest do
  @moduledoc """
  An unauthenticated request to /oauth/authorize must not register a client with an attacker-chosen client_id and redirect_uri, must not register one when its metadata cannot be fetched, and no client registered through the open paths gets admin scopes.
  """
  use Bonfire.OpenID.ConnCase, async: false
  use Repatch.ExUnit
  import Ecto.Query
  import Bonfire.Common.Config, only: [repo: 0]

  alias Bonfire.OpenID.Provider.CIMD
  alias Bonfire.OpenID.Provider.ClientApps
  alias Bonfire.UI.Common.Testing.Helpers

  @moduletag capture_log: true

  @evil "https://evil.local/cb"

  setup do
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)
    :ok
  end

  defp authorize_path(client_id, redirect_uri) do
    "/oauth/authorize?" <>
      URI.encode_query(%{
        "client_id" => client_id,
        "redirect_uri" => redirect_uri,
        "response_type" => "code",
        "scope" => "read"
      })
  end

  defp clients_with_redirect(uri) do
    repo().all(from c in Boruta.Ecto.Client, where: ^uri in c.redirect_uris)
  end

  defp guest, do: Phoenix.ConnTest.build_conn()

  defp signed_in do
    account = Helpers.fake_account!()
    user = Helpers.fake_user!(account)
    conn(user: user, account: account)
  end

  defp consent_screen?(conn) do
    conn.status == 200 and conn.resp_body =~ "oauth_consent_allow"
  end

  defp sent_to_evil?(conn) do
    case Plug.Conn.get_resp_header(conn, "location") do
      [location | _] -> String.contains?(location, "evil.local")
      _ -> false
    end
  end

  describe "made-up client_id with an attacker redirect_uri" do
    test "a guest request does not register a client" do
      name = "some-made-up-name-#{Faker.UUID.v4()}"

      guest() |> get(authorize_path(name, @evil))

      assert ClientApps.get_by_id(ClientApps.id_or_name_to_id(name)) == nil
      assert clients_with_redirect(@evil) == []
    end

    test "a signed-in request does not register a client or render a consent screen for it" do
      name = "some-made-up-name-#{Faker.UUID.v4()}"

      conn = signed_in() |> get(authorize_path(name, @evil))

      refute consent_screen?(conn)
      refute sent_to_evil?(conn)
      assert clients_with_redirect(@evil) == []
    end

    test "a client_id first claimed with one redirect_uri cannot be claimed first by an attacker" do
      name = "squat-me-#{Faker.UUID.v4()}"

      guest() |> get(authorize_path(name, @evil))

      # whoever registers this name afterwards must not find the attacker's redirect_uri on it
      refute match?(
               %{redirect_uris: [@evil | _]},
               ClientApps.get_by_id(ClientApps.id_or_name_to_id(name))
             )
    end
  end

  describe "client metadata (CIMD) fetch failure" do
    test "does not register a client for the client_id URL" do
      client_id = "https://metadata-fails.local/client.json"
      Repatch.patch(CIMD, :fetch, fn ^client_id -> {:error, "metadata unreachable"} end)

      conn = guest() |> get(authorize_path(client_id, @evil))

      assert ClientApps.get_by_id(ClientApps.id_or_name_to_id(client_id)) == nil
      assert clients_with_redirect(@evil) == []
      assert conn.status == 400
    end
  end

  describe "scopes of clients registered through open paths" do
    test "an authorize-registered client has no admin scopes" do
      name = "scopes-check-#{Faker.UUID.v4()}"

      guest() |> get(authorize_path(name, @evil))

      scopes = scope_names(ClientApps.get_by_id(ClientApps.id_or_name_to_id(name)))
      refute Enum.any?(scopes, &String.starts_with?(&1, "admin:"))
    end

    test "an /api/v1/apps-registered client has no admin scopes" do
      response =
        guest()
        |> put_req_header("content-type", "application/json")
        |> post(
          "/api/v1/apps",
          Jason.encode!(%{
            "client_name" => "Scopes app #{Faker.UUID.v4()}",
            "redirect_uris" => "https://client.local/callback",
            "scopes" => "read"
          })
        )
        |> json_response(200)

      scopes = scope_names(ClientApps.get_by_id(response["client_id"]))
      refute Enum.any?(scopes, &String.starts_with?(&1, "admin:"))
    end
  end

  describe "control: an app registered through /api/v1/apps" do
    test "can start the authorize flow to its own redirect_uri" do
      redirect = "https://client.local/callback"

      response =
        guest()
        |> put_req_header("content-type", "application/json")
        |> post(
          "/api/v1/apps",
          Jason.encode!(%{
            "client_name" => "Control app #{Faker.UUID.v4()}",
            "redirect_uris" => redirect,
            "scopes" => "read"
          })
        )
        |> json_response(200)

      conn = signed_in() |> get(authorize_path(response["client_id"], redirect))

      assert consent_screen?(conn)
    end
  end

  defp scope_names(nil), do: []

  defp scope_names(client) do
    client
    |> repo().preload(:authorized_scopes)
    |> Map.get(:authorized_scopes)
    |> Enum.map(& &1.name)
  end
end
