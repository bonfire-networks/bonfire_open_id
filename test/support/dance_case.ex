defmodule Bonfire.OpenID.DanceCase do
  use ExUnit.CaseTemplate
  use Bonfire.Common.Config
  import Tesla.Mock
  import Untangle
  import Bonfire.UI.Common.Testing.Helpers
  alias Bonfire.Common.TestInstanceRepo

  setup_all tags do
    info("Start with a DanceTest")

    Bonfire.Common.Test.Interactive.setup_test_repo(tags)

    on_exit(fn ->
      info("Done with a DanceTest")
      # this callback needs to checkout its own connection since it
      # runs in its own process
      # :ok = Ecto.Adapters.SQL.Sandbox.checkout(repo())
      # Ecto.Adapters.SQL.Sandbox.mode(repo(), :auto)

      # Object.delete(actor1)
      # Object.delete(actor2)
      :ok
    end)

    TestInstanceRepo.apply(fn ->
      if !Bonfire.Boundaries.Circles.exists?(Bonfire.Boundaries.Circles.get_id!(:local)) do
        info("Seems boundary fixtures are missing on test instance, running now")
        Bonfire.Boundaries.Scaffold.insert()
      end
    end)

    # Set a known password for the test user
    test_password = "test_password_123"

    [
      local: fake_user!(%{credential: %{password: test_password}}, %{name: "Local"}),
      remote:
        TestInstanceRepo.apply(fn ->
          fake_user!(%{credential: %{password: test_password}}, %{name: "Remote"})
        end),
      test_password: test_password
    ]
  end

  @doc """
  Wraps a function call and ensures Boruta.Config.repo() is synced with Config.repo() after the call.
  Use for all Req.get/Req.post calls in tests to avoid global repo contamination.
  """
  def apply_with_repo_sync(fun) when is_function(fun, 0) do
    result = fun.()

    if Boruta.Config.repo() != Bonfire.Common.Config.repo() do
      Bonfire.Common.Config.put([Boruta.Oauth, :repo], Bonfire.Common.Config.repo())
    end

    result
  end
end

defmodule ReqCookieJar do
  use Agent

  def new() do
    Agent.start_link(fn -> [] end, name: __MODULE__)
  end

  defp get_cookies do
    Agent.get(__MODULE__, & &1)
  end

  defp set_cookies([]), do: nil

  defp set_cookies(cookies) when is_list(cookies) do
    Agent.update(__MODULE__, fn _ -> cookies end)
  end

  def attach(%Req.Request{} = request) do
    request
    |> Req.Request.append_response_steps(
      cookie_jar: fn {req, res} ->
        Req.Response.get_header(res, "set-cookie")
        |> set_cookies()

        {req, res}
      end
    )
    |> Req.Request.append_request_steps(
      cookie_jar: fn req ->
        cookies = get_cookies()

        if cookies != [] do
          # Join multiple cookies with "; " as per HTTP specification
          cookie_string = Enum.join(cookies, "; ")
          Req.Request.put_header(req, "cookie", cookie_string)
        else
          req
        end
      end
    )
  end
end
