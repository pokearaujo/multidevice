import { WapJid } from '../proto/WapJid';
import { Key, KeyPair, PreKey, SignedKeyPair } from '../utils/Curve';

var AWS = require('aws-sdk');
AWS.config.update({
  region: 'eu-west-1',
  endpoint: "http://localhost:8000"
});

class StorageService {
  private dynamoDb;
  private dynamoDocClient;
  private dynamoDbTable = 'wip_multi_device';
  private currentUserNumber = '+447467917138';//TODO - replace this for some multi-tenancy number
  private localStorage: {
    [key: string]: any;
  } = {};
  //currently running 2 views of data - one for DB, one for local :-( )
  private dbStorageItem: {
    [key: string]: any;
  } = {};

  public async initStorage() {
    this.dynamoDb = new AWS.DynamoDB({ apiVersion: '2012-08-10' });
    this.dynamoDocClient = new AWS.DynamoDB.DocumentClient();
    await this.loadStorage(this.currentUserNumber);
  };

  public async clearAll() {
    console.log('++++++++++++ storageService clearAll: ++++++++++++');
    this.localStorage = {};
    this.dbStorageItem = {};
    await this.deleteFromDb(this.currentUserNumber);
  }

  public get<T = any>(key: string): T {
    return this.localStorage.data[key] ?? null;
  }

  public async getOrSave<T = any>(key: string, callback: Function): Promise<T> {
    if (this.localStorage && this.localStorage.data && this.localStorage.data[key]) {
      return this.localStorage.data[key];
    }

    const createdData = await callback();
    this.localStorage.data[key] = createdData;

    this.dbStorageItem.data[key] = this.objToJson(createdData);
    await this.persistToDb();

    return createdData;
  }

  public async save<T = any>(key: string, data: any): Promise<T> {
    this.localStorage.data[key] = data;
    this.dbStorageItem.data[key] = this.objToJson(data);

    await this.persistToDb();
    return data;
  }

  private async loadStorage(currentUserNumber) {
    await this.dynamoDb.describeTable({ TableName: 'wip_multi_device' }, function (err, data) {
      if (err) {
        throw new Error(`Error, wip_multi_device table does not exist: ${err}`);
      }
    });

    var fetchParams = {
      TableName: this.dynamoDbTable,
      Key: {
        'client_number': currentUserNumber
      }
    };

    // Call DynamoDB to read the item from the table
    await this.dynamoDocClient.get(fetchParams, async (err, data) => {
      if (err) {
        console.log('No data exists for ', currentUserNumber, ': ', err);
      } else {
        this.localStorage = { client_number: currentUserNumber, data: {} };
        this.dbStorageItem = { client_number: currentUserNumber, data: {} };
        let rawData = data.Item;
        if (!rawData) {
          console.log('------ no rawData bruh');
        }
        else {
          const jsonifiedData = JSON.parse(JSON.stringify(rawData.data));
          this.localStorage.data = this.parseData(jsonifiedData);
          this.dbStorageItem.data = rawData.data ;
        }
      }
    });
  }

  // iterate over data items
  private parseData = (data: any) => {
    const out: {
      [key: string]: any;
    } = {};

    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        let element = data[key];

        if (Array.isArray(element)) {
          const temp = [];
          for (const obj of element) {
            temp.push(obj?.type ? this.castElement(obj) : obj);
          }
          out[key] = temp;
          continue;
        }
        if (element?.type) {
          element = this.castElement(element);
        }
        out[key] = element;
      }
    }
    return out;
  };

  // build typescript objects from object 'tpye' field
  private castElement(element: any) {

    switch (element.type) {
      case 'key':
        return Key.parse(element);
      case 'keyPair':
        return KeyPair.parse(element);
      case 'signedKeyPair':
        return SignedKeyPair.parse(element);
      case 'preKey':
        return PreKey.parse(element);
      case 'wapJid':
        return WapJid.parse(element);

      default:
        throw new Error(`invalid cast element: ${element.type}`);
    }
  }

  private async persistToDb() {
    var insertParams = {
      TableName: this.dynamoDbTable,
      Item: {
        'client_number': this.currentUserNumber,
        'data': this.dbStorageItem.data
      }
    };

    // Call DynamoDB to add the item to the table
    await this.dynamoDocClient.put(insertParams, (err, data) => {
      if (err) {
        console.log('Error: failed to save data: ', err);
      }
    });
  }

  private async deleteFromDb(client_number: string) {
    var params = {
      TableName: this.dynamoDbTable,
      Key: {
        'client_number': this.currentUserNumber
      }
    };

    await this.dynamoDocClient.delete(params, (err, data) => {
      if (err) {
        console.log('Error: failed to delete data: ', err);
      }
    });
  }

  // adds type to a new peice of data ands returns JSON
  private objToJson(data: any) {
    let type;
    if (data instanceof KeyPair) {
      type = data.toJSON();
    } else if (data instanceof WapJid) {
      type = data.toJSON();
    } else if (data instanceof Key) {
      type = data.toJSON();
    } else if (data instanceof PreKey) {
      type = data.toJSON();
    } else if (data instanceof SignedKeyPair) {
      type = data.toJSON();
    }

    if (type) {
      return type;
    }
    return data;
  }
}

export const storageService = new StorageService();
