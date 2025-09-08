import { ApiProperty} from '@nestjs/swagger';
import { Role } from '../../auth/enums/role.enum';

    export class UserMeDto {

        @ApiProperty({ example: '12345' })
        id!: string;

        @ApiProperty({ example: 'davi_rinaldi' })
        username!: string;

        @ApiProperty({ example: 'davi@gmail.com'})
        email!: string;

        @ApiProperty({ type: String, format: 'date-time' })
        createdAt!: Date;

        @ApiProperty({ 
          enum: Role, 
          example: Role.USER,
          description: 'User role for authorization'
        })
        role!: Role;
}