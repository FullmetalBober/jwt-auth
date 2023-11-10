import {
  Controller,
  Body,
  Get,
  Post,
  UseGuards,
  Request,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { LocalAuthGuard } from 'src/auth/local-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  login(@Request() req) {
    // return this.usersService.login(body);
    return req.user;
  }

  @Get('profile')
  getProfile(@Body() body: any) {
    // return this.usersService.getProfile(body);
    return body;
  }
}
