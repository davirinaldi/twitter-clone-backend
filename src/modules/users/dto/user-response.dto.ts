import { ApiProperty, OmitType } from '@nestjs/swagger';
import { Role } from '../../auth/enums/role.enum';

export class UserResponseDto {
  @ApiProperty({ example: '12345' })
  id!: string;

  @ApiProperty({ example: 'davi_rinaldi' })
  username!: string;

  @ApiProperty({ type: String, format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ 
    enum: Role, 
    example: Role.USER,
    description: 'User role for authorization'
  })
  role!: Role;
}

// Variante “pública” sem createdAt
export class UserPublicDto extends OmitType(UserResponseDto, ['createdAt'] as const) {}
