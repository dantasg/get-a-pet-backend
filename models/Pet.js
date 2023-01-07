const mongoose = require('mongoose');
const { Schema } = mongoose;

const Pet = mongoose.model(
  'Pet',
  new Schema(
    {
      name: {
        type: 'string',
        required: true,
      },
      age: {
        type: 'number',
        required: true,
      },
      weight: {
        type: 'number',
        required: true,
      },
      color: {
        type: 'string',
        required: true,
      },
      images: {
        type: 'array',
        required: true,
      },
      available: {
        type: 'boolean',
      },
      user: Object,
      adopter: Object,
    },
    { timestamps: true },
  ),
);

module.exports = Pet;
