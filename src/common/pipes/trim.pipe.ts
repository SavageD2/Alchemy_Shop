import { PipeTransform, Injectable } from '@nestjs/common';

@Injectable()
export class TrimPipe implements PipeTransform {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transform(value: any) {
    if (typeof value === 'string' || value === null) {
      return typeof value === 'string' ? value.trim() : value;
    }

    this.trimArrayObject(value);
    return value;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
// eslint-disable-next-line @typescript-eslint/no-explicit-any
  private trimArrayObject(body: any) {
    Object.keys(body).forEach((key) => {
      if (typeof body[key] === 'string') {
        body[key] = body[key].trim();
      } else if (typeof body[key] === 'object' && body[key] !== null) {
        this.trimArrayObject(body[key]);
      }
    });
  }
}