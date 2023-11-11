import { Controller, Get, Post, UseGuards, Request } from '@nestjs/common';
import { UsersService } from './users.service';
import { LocalAuthGuard } from 'src/_auth/local-auth.guard';
import { AuthService } from 'src/_users/auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
  ) {}

  // @UseGuards(LocalAuthGuard)
  // @Post('login')
  // login(@Request() req) {
  //   // return this.usersService.login(body);
  //   return this.authService.login(req.user);
  // }

  // @UseGuards(JwtAuthGuard)
  // @Get('profile')
  // getProfile(@Request() req) {
  //   // return this.usersService.getProfile(body);
  //   return req.user;
  // }
}
