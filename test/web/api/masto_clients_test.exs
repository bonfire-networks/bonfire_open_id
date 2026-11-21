defmodule Bonfire.OpenID.Web.MastoClientsTest do
  @moduledoc """
  Replays each Mastodon client app's login against the API (its own registration body, redirect URI and token request), then checks what it would decode. One test per app, so each fails on its own.

  Excluded by default (`:masto_clients`); run it with `--only masto_clients`.
  """
  use Bonfire.OpenID.ConnCase, async: false

  alias Bonfire.API.MastoCompat.Test.MastoClients
  alias Bonfire.API.MastoCompat.Test.MastoSeed
  alias Bonfire.OpenID.Test.OAuthWalk

  @moduletag :masto_clients
  @moduletag capture_log: true

  # what every app loads right after login: {path, entity, :one | :list}
  @views [
    {"/api/v1/accounts/verify_credentials", "Account", :one},
    {"/api/v1/timelines/home", "Status", :list},
    {"/api/v1/timelines/public", "Status", :list},
    {"/api/v1/notifications", "Notification", :list}
  ]

  setup do
    previous = Application.get_env(:bonfire_open_id, :oauth_module)
    Application.put_env(:bonfire_open_id, :oauth_module, Boruta.Oauth)
    on_exit(fn -> Application.put_env(:bonfire_open_id, :oauth_module, previous) end)

    seed = MastoSeed.seed!()
    {:ok, seed: seed, session: conn(user: seed.a, account: seed.account)}
  end

  for profile <- MastoClients.profiles() do
    @profile profile

    test "#{profile.id} can register, log in and decode its first screens", c do
      problems =
        preflight_problems(@profile) ++
          case log_in(@profile, c.session) do
            {:ok, token} -> view_problems(@profile, token, c.seed)
            {:error, problem} -> [problem]
          end

      assert problems == [], "#{@profile.id}:\n  - " <> Enum.join(problems, "\n  - ")
    end
  end

  defp preflight_problems(profile) do
    Enum.flat_map(profile.preflight, fn {path, entity} ->
      check(profile, build_conn() |> get(path), path, entity, :one)
    end)
  end

  defp log_in(profile, session) do
    %{encoding: encoding, redirect_uri: redirect_uri} = profile.register

    registered =
      OAuthWalk.post_encoded(
        build_conn(),
        "/api/v1/apps",
        %{
          "client_name" => "#{profile.id}",
          "redirect_uris" => redirect_uri,
          "scopes" => MastoClients.scopes()
        },
        encoding
      )

    with %{status: 200} <- registered,
         %{"client_id" => client_id, "client_secret" => secret} <- json_response(registered, 200) do
      code =
        session
        |> OAuthWalk.approve(
          OAuthWalk.authorization_path("oauth", %{
            "response_type" => "code",
            "client_id" => client_id,
            "redirect_uri" => redirect_uri,
            "scope" => MastoClients.scopes()
          })
        )
        |> OAuthWalk.callback_code()

      token =
        OAuthWalk.exchange(
          "oauth",
          %{
            "grant_type" => "authorization_code",
            "code" => code,
            "client_id" => client_id,
            "client_secret" => secret,
            "redirect_uri" => redirect_uri
          },
          profile.token
        )

      {:ok, token["access_token"]}
    else
      %Plug.Conn{status: status} ->
        {:error, "POST /api/v1/apps with #{redirect_uri}: #{status}"}

      other ->
        {:error, "POST /api/v1/apps with #{redirect_uri}: unexpected body #{inspect(other)}"}
    end
  end

  defp view_problems(profile, token, seed) do
    # the reply's context has the seed post as ancestor; the leaf's is empty once its parent is deleted, so it can't be checked for shape
    views = @views ++ [{"/api/v1/statuses/#{seed.reply.id}/context", "Context", :one}]

    Enum.flat_map(views, fn {path, entity, shape} ->
      conn = build_conn() |> put_req_header("authorization", "Bearer #{token}") |> get(path)
      check(profile, conn, path, entity, shape)
    end)
  end

  defp check(_profile, %{status: status}, path, _entity, _shape) when status != 200,
    do: ["GET #{path}: #{status}"]

  defp check(profile, conn, path, "Context", :one) do
    %{"ancestors" => ancestors, "descendants" => descendants} = json_response(conn, 200)
    list_problems(profile, path, "Status", ancestors ++ descendants)
  end

  defp check(profile, conn, path, entity, :one),
    do: MastoClients.problems(profile, entity, json_response(conn, 200), "GET #{path}: ")

  defp check(profile, conn, path, entity, :list),
    do: list_problems(profile, path, entity, json_response(conn, 200))

  defp list_problems(_profile, path, _entity, []),
    do: ["GET #{path}: empty, so nothing was checked"]

  defp list_problems(profile, path, entity, items) do
    items
    |> Enum.with_index()
    |> Enum.flat_map(fn
      {nil, index} -> ["GET #{path}: item #{index} is null"]
      {item, index} -> MastoClients.problems(profile, entity, item, "GET #{path}: #{index}.")
    end)
  end
end
