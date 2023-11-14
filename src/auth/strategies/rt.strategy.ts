import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(private config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        RtStrategy.extractJWTFromCookie,
      ]),
      secretOrKey: config.get('RT_SECRET'),
      passReqToCallback: true,
    });
  }

  private static extractJWTFromCookie(req: Request): string | null {
    const token = req.cookies.refresh_token;
    if (req.cookies && token) return token;
    return null;
  }

  validate(req: Request, payload: any) {
    let refreshToken = req.get('authorization')?.replace('Bearer ', '').trim();
    if (!refreshToken) refreshToken = req.cookies.refresh_token;

    return {
      ...payload,
      refreshToken,
    };
  }
}
