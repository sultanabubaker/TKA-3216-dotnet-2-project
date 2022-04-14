using System;
namespace GoodIdSdk2.Authentication
{
    // TODO DELETE
    public class GoodIdEndpointResult
    {
        public enum ActionType
        {
            NONE,
            REDIRECT,
            OUTPUT
        };

        public ActionType Action { get; }
        public String Data { get; }

        public GoodIdEndpointResult(ActionType action, String data) {
            Action = action;
            Data = data;
        }
    }
}
