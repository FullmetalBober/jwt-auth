import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';

type JwtPayload = {
  sub: number;
  email: string;
};

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        AtStrategy.extractJWTFromCookie,
      ]),
      secretOrKey: config.get('AT_SECRET'),
    });
  }

  private static extractJWTFromCookie(req: Request): string | null {
    const token = req.cookies.access_token;
    if (req.cookies && token) return token;
    return null;
  }

  validate(payload: JwtPayload) {
    return payload;
  }
}
