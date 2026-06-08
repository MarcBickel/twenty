import { type Request } from 'express';
import { type TokenSet } from 'openid-client';

import { AuthException } from 'src/engine/core-modules/auth/auth.exception';

import { OIDCAuthStrategy } from './oidc.auth.strategy';

describe('OIDCAuthStrategy.validate', () => {
  const tokenset = { claims: () => ({}) } as unknown as TokenSet;
  const request = {} as Request;

  const buildContext = (userinfo: Record<string, unknown>) => ({
    client: { userinfo: jest.fn().mockResolvedValue(userinfo) },
    extractState: jest.fn().mockReturnValue({
      identityProviderId: 'identity-provider-id',
      workspaceInviteHash: undefined,
    }),
  });

  const invokeValidate = (context: ReturnType<typeof buildContext>) => {
    const done = jest.fn();

    return OIDCAuthStrategy.prototype.validate
      .call(
        context as unknown as OIDCAuthStrategy,
        request,
        tokenset,
        done as Parameters<OIDCAuthStrategy['validate']>[2],
      )
      .then(() => done);
  };

  it('rejects when the identity provider reports the email as not verified', async () => {
    const done = await invokeValidate(
      buildContext({
        email: 'user@workspace.example',
        email_verified: false,
      }),
    );

    expect(done).toHaveBeenCalledTimes(1);
    expect(done.mock.calls[0][0]).toBeInstanceOf(AuthException);
    expect(done.mock.calls[0][1]).toBeUndefined();
  });

  it('accepts when the email is verified', async () => {
    const done = await invokeValidate(
      buildContext({
        email: 'user@workspace.example',
        email_verified: true,
      }),
    );

    expect(done).toHaveBeenCalledTimes(1);
    expect(done.mock.calls[0][0]).toBeNull();
    expect(done.mock.calls[0][1]).toEqual(
      expect.objectContaining({ email: 'user@workspace.example' }),
    );
  });

  it('accepts when the email_verified claim is absent', async () => {
    const done = await invokeValidate(
      buildContext({ email: 'user@workspace.example' }),
    );

    expect(done).toHaveBeenCalledTimes(1);
    expect(done.mock.calls[0][0]).toBeNull();
    expect(done.mock.calls[0][1]).toEqual(
      expect.objectContaining({ email: 'user@workspace.example' }),
    );
  });
});
