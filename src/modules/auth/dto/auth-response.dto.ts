import { ApiProperty } from '@nestjs/swagger';
import { UserPublicDto } from '../../users/dto/user-response.dto';

export class AuthResponseDto {
  @ApiProperty({ example: 'jwt_access_token' })
  access_token!: string;

  @ApiProperty({ example: 'jwt_refresh_token' })
  refresh_token!: string;

  @ApiProperty({ type: () => UserPublicDto })
  user!: UserPublicDto;
}
