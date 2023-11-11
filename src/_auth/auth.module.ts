import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from 'src/_users/users.module';
import { AuthService } from '../_users/auth.service';
import { LocalStrategy } from '../_users/local.strategy';
// import { SessionSerializer } from './session.serializer';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '60s' },
    }),
  ], //PassportModule.register({ session: true }) //! session code
  providers: [AuthService, LocalStrategy], //SessionSerializer //! session code
  exports: [AuthService],
})
export class AuthModule {}
