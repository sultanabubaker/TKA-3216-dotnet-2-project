using GoodId.Core.Exceptions;
using NUnit.Framework;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using GoodId.Core.Helpers.ClaimChecker;

namespace GoodId.Core.Tests.Helpers.ClaimChecker
{
    [TestFixture]
    public class AudienceCheckerTest
    {
        [Test]
        public void TestSupportedClaimWithEmptyExpectedAudience()
        {
            ValidationException ex = Assert.Throws<ValidationException>(
            () => { new AudienceChecker(string.Empty); });
            Assert.That(ex.Message, Is.EqualTo("Missing audience"));
        }
        [Test]
        public void TestSupportedClaimWithEmptyAudience()
        {
            var audience = "TestAudience";
            var audienceChecker = new AudienceChecker(audience);

            ValidationException ex = Assert.Throws<ValidationException>(
            () => { audienceChecker.CheckClaim(string.Empty); });
            Assert.That(ex.Message, Is.EqualTo("Invalid audience"));
        }

        [Test]
        public void TestSupportedClaimWithGoodAudience()
        {
            var audience = "TestAudience";
            var audienceChecker = new AudienceChecker(audience);
            Assert.DoesNotThrow(() => { audienceChecker.CheckClaim(audience); });
        }

        [Test]
        public void TestSupportedClaimWithDifferentAudiences()
        {
            var audienceA = "TestAudienceA";
            var audienceB = "TestAudienceB";

            var audienceChecker = new AudienceChecker(audienceA);

            ValidationException ex = Assert.Throws<ValidationException>(
            () => { audienceChecker.CheckClaim(audienceB); });
            Assert.That(ex.Message, Is.EqualTo("Invalid audience"));
        }
    }
}
